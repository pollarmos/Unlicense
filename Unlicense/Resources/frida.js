"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();
let oepTracingListeners = [];
let oepReached = false;

// DLLs-related
let skipDllOepInstr32 = null;
let skipDllOepInstr64 = null;
let dllOepCandidate = null;

// TLS-related
let skipTlsInstr32 = null;
let skipTlsInstr64 = null;
let tlsCallbackCount = 0;

function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
}

function initializeTrampolines() {
    const instructionsBytes = new Uint8Array([
        0xC3,                                          // ret
        0xC2, 0x0C, 0x00,                              // ret 0x0C
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,            // mov eax, 1; ret
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00 // mov eax, 1; ret 0x0C
    ]);

    let bufferPointer = Memory.alloc(instructionsBytes.length);
    Memory.protect(bufferPointer, instructionsBytes.length, 'rwx');
    // [수정된 부분] 안전하게 1바이트씩 씁니다.
    for (var i = 0; i < instructionsBytes.length; i++) {
        bufferPointer.add(i).writeU8(instructionsBytes[i]);
    }

    log("Trampolines wrote manually at: " + bufferPointer);

    skipTlsInstr64 = bufferPointer;
    skipTlsInstr32 = bufferPointer.add(0x1);
    skipDllOepInstr64 = bufferPointer.add(0x4);
    skipDllOepInstr32 = bufferPointer.add(0xA);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function notifyOepFound(dumpedModule, oepCandidate) {
    oepReached = true;
    
    // Make OEP ranges readable and writeable during the dumping phase
    setOepRangesProtection('rw-');
    // Remove hooks used to find the OEP
    removeOepTracingHooks();

    let isDotNetInitialized = isDotNetProcess();
    send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': isDotNetInitialized })
    let sync_op = recv('block_on_oep', function (_value) { });
    // Note: never returns
    sync_op.wait();
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function makeOepRangesInaccessible(dumpedModule, expectedOepRanges) {
    // Ensure potential OEP ranges are not accessible
    expectedOepRanges.forEach((oepRange) => {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const expectedSectionSize = oepRange[1];
        Memory.protect(sectionStart, expectedSectionSize, '---');
        log("DEBUG: Set OEP section to inaccessible (---).");
        originalPageProtections.set(sectionStart.toString(), expectedSectionSize);
    });
}

function setOepRangesProtection(protection) {
    // Set pages' protection
    originalPageProtections.forEach((size, address_str, _map) => {
        Memory.protect(ptr(address_str), size, protection);
    });
}

function removeOepTracingHooks() {
    oepTracingListeners.forEach(listener => {
        listener.detach();
    })
    oepTracingListeners = [];
}

function registerExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let oepCandidate = exp.context.pc;
        let threadId = Process.getCurrentThreadId();

        if (exp.memory != null) {
            // Weird case where executing code actually only triggers a "read"
            // access violation on inaccessible pages. This can happen on some
            // 32-bit executables.
            if (exp.memory.operation == "read" && exp.memory.address.equals(exp.context.pc)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    return true;
                }

                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                // Report the potential OEP
                notifyOepFound(dumpedModule, oepCandidate);
            }

            // If the access violation is not an execution, "allow" the operation.
            // Note: Pages will be reprotected on the next call to
            // `NtProtectVirtualMemory`.
            if (exp.memory.operation != "execute") {
                Memory.protect(exp.memory.address, Process.pageSize, "rw-");
                return true;
            }
        }

        let expectionHandled = false;
        expectedOepRanges.forEach((oepRange) => {
            const sectionStart = dumpedModule.base.add(oepRange[0]);
            const sectionSize = oepRange[1];
            const sectionRange = { base: sectionStart, size: sectionSize };

            if (rangeContainsAddress(sectionRange, oepCandidate)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    expectionHandled = true;
                    return;
                }
                
                if (moduleIsDll) {
                    // Save the potential OEP and and skip `DllMain` (`DLL_PROCESS_ATTACH`).
                    // Note: When dumping DLLs we have to release the loader
                    // lock before starting to dump.
                    // Other threads might call `DllMain` with the `DLL_THREAD_ATTACH`
                    // or `DLL_THREAD_DETACH` reasons later so we also skip the `DllMain`
                    // even after the OEP has been reached.
                    if (!oepReached) {
                        log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                        dllOepCandidate = oepCandidate;
                    } 

                    skipDllEntryPoint(exp.context);
                    expectionHandled = true;
                    return;
                }

                // Report the potential OEP
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                notifyOepFound(dumpedModule, oepCandidate);
            }
        });

        return expectionHandled;
    });
    log("Exception handler registered");
}

function isTlsCallback(exceptionCtx, dumpedModule) {
    if (Process.arch == "x64") {
        // If we're in a TLS callback, the first argument is the
        // module's base address
        let moduleBase = exceptionCtx.rcx;
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        // If we're in a TLS callback, the second argument is the
        // reason (from 0 to 3).
        let reason = exceptionCtx.rdx;
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    }
    else if (Process.arch == "ia32") {
        let sp = exceptionCtx.sp;

        let moduleBase = sp.add(0x4).readPointer();
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        let reason = sp.add(0x8).readPointer();
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

function skipTlsCallback(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `ret` instruction
        exceptionCtx.rip = skipTlsInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `ret 0xC` instruction
        exceptionCtx.eip = skipTlsInstr32;
    }
}

function skipDllEntryPoint(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `mov eax, 1; ret` instructions
        exceptionCtx.rip = skipDllOepInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `mov eax, 1; ret 0xC` instructions
        exceptionCtx.eip = skipDllOepInstr32;
    }
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName, expectedOepRanges) {

        log(`Setting up OEP tracing for "${moduleName}"`);

        // 1. 위에서 만든 함수 호출
        initializeTrampolines();

        // [사용자님이 원하시던 디버깅 로그 코드 시작]
        log("DEBUG: [1] initializeTrampolines completed");

        // [디버깅 코드 추가]
        log("Type of moduleName: " + typeof moduleName);
        log("Is initializeTrampolines defined?: " + (typeof initializeTrampolines));

        let targetIsDll = moduleName.endsWith(".dll");
        let dumpedModule = null;

        initializeTrampolines();

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            log("DEBUG: [2] Attempting to call Process.findModuleByName");
            if (typeof Process.findModuleByName !== 'function') {
                log("FATAL: Process.findModuleByName is NOT a function!");
            }
            dumpedModule = Process.findModuleByName(moduleName);
            log("DEBUG: [3] dumpedModule found: " + dumpedModule);
        }

        // 전역 Module 대신 Process를 통해 안전하게 찾습니다.
        var loadDll = null;
        var ntdll = Process.findModuleByName("ntdll.dll");
        if (ntdll === null) {
            ntdll = Process.findModuleByName("ntdll");
        }

        if (ntdll !== null) {
            log("DEBUG: [4] ntdll module found (" + ntdll.base + ")");
            // 모듈 내부에서 직접 함수 찾기 (호환성 확보)
            var exports = ntdll.enumerateExports();
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name === 'LdrLoadDll') {
                    loadDll = exports[i].address;
                    break;
                }
            }
        }

        if (loadDll === null) {
            // 혹시 못 찾았을 경우 대비
            if (ntdll !== null) loadDll = ntdll.findExportByName('LdrLoadDll');
        }

        if (loadDll === null) {
            log("FATAL: Could not find LdrLoadDll function.");
            return;
        }

        log("DEBUG: [5] LdrLoadDll address obtained: " + loadDll);

        log("DEBUG: [6] Attempting to call Interceptor.attach");
        if (typeof Interceptor.attach !== 'function') {
            log("FATAL: Interceptor.attach is NOT a function!");
        }

        const loadDllListener = Interceptor.attach(loadDll, {
            onLeave: function (_args) {
                // If `dllOepCandidate` is set, proceed with the dumping
                // but only once (for our target). Then let other executions go
                // through as it's not DLLs we're intersted in.
                if (dllOepCandidate != null && !oepReached) {
                    notifyOepFound(dumpedModule, dllOepCandidate);
                }
            }
        });

        log("DEBUG: [7] Interceptor.attach succeeded");
        oepTracingListeners.push(loadDllListener);
        log("DEBUG: [8] loadDllListener registered");

        let exceptionHandlerRegistered = false;
        // [수정] NtProtectVirtualMemory 함수 안전하게 찾기
        var ntProtectVirtualMemory = null;
        var ntdllForProtect = Process.findModuleByName("ntdll.dll");
        if (ntdllForProtect === null) ntdllForProtect = Process.findModuleByName("ntdll");

        if (ntdllForProtect !== null) {
            // 안전하게 루프 돌며 찾기
            var exports = ntdllForProtect.enumerateExports();
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name === 'NtProtectVirtualMemory') {
                    ntProtectVirtualMemory = exports[i].address;
                    break;
                }
            }
            // 못 찾았으면 Zw... 로 한번 더 시도
            if (ntProtectVirtualMemory === null) {
                for (var i = 0; i < exports.length; i++) {
                    if (exports[i].name === 'ZwProtectVirtualMemory') {
                        ntProtectVirtualMemory = exports[i].address;
                        break;
                    }
                }
            }
        }

        if (ntProtectVirtualMemory != null) {
            log("DEBUG: [9] NtProtectVirtualMemory address obtained: " + ntProtectVirtualMemory);

            // 여기서부터는 기존 로직과 동일합니다.
            const ntProtectVirtualMemoryListener = Interceptor.attach(ntProtectVirtualMemory, {
                onEnter: function (args) {
                    let addr = args[1].readPointer();
                    if (dumpedModule != null && addr.equals(dumpedModule.base)) {
                        // Reset potential OEP ranges to not accessible
                        makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                        if (!exceptionHandlerRegistered) {
                            registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                            exceptionHandlerRegistered = true;
                            log("DEBUG: [10] Exception handler registered");
                        }
                    }
                }
            });
            oepTracingListeners.push(ntProtectVirtualMemoryListener);
            log("DEBUG: [11] NtProtectVirtualMemory hooked");
        } else {
            log("FATAL: Could not find NtProtectVirtualMemory function.");
        }

        // Hook `ntdll.RtlActivateActivationContextUnsafeFast` on exit as a mean
        // to get called after new PE images are loaded and before their entry
        // point is called. Needed to unpack DLLs.
        // [수정된 코드] RtlActivateActivationContextUnsafeFast 안전하게 찾기
        let initializeFusionHooked = false;
        var activateActivationContext = null;

        // 1. ntdll 모듈 확인
        var ntdllForCtx = Process.findModuleByName("ntdll.dll");
        if (ntdllForCtx === null) ntdllForCtx = Process.findModuleByName("ntdll");

        // 2. 함수 주소 검색 (안전 모드)
        if (ntdllForCtx !== null) {
            var exports = ntdllForCtx.enumerateExports();
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name === 'RtlActivateActivationContextUnsafeFast') {
                    activateActivationContext = exports[i].address;
                    break;
                }
            }
        }

        // 3. 못 찾았을 경우 대비 (기존 방식 시도)
        if (activateActivationContext === null && ntdllForCtx !== null) {
            activateActivationContext = ntdllForCtx.findExportByName('RtlActivateActivationContextUnsafeFast');
        }

        if (activateActivationContext !== null) {
            log("DEBUG: [13] RtlActivateActivationContextUnsafeFast address obtained: " + activateActivationContext);

            const activateActivationContextListener = Interceptor.attach(activateActivationContext, {
                onLeave: function (_args) {
                    if (dumpedModule == null) {
                        dumpedModule = Process.findModuleByName(moduleName);
                        if (dumpedModule == null) {
                            return;
                        }
                        log(`Target module has been loaded (thread #${this.threadId}) ...`);
                    }
                    // After this, the target module is loaded.

                    if (targetIsDll) {
                        if (!exceptionHandlerRegistered) {
                            makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                            registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                            exceptionHandlerRegistered = true;
                        }
                    }

                    // Hook `clr.InitializeFusion` if present.
                    if (!initializeFusionHooked) {
                        var initializeFusion = null;
                        var clrModule = Process.findModuleByName("clr.dll");
                        if (clrModule === null) clrModule = Process.findModuleByName("clr");

                        if (clrModule !== null) {
                            var clrExports = clrModule.enumerateExports();
                            for (var k = 0; k < clrExports.length; k++) {
                                if (clrExports[k].name === 'InitializeFusion') {
                                    initializeFusion = clrExports[k].address;
                                    break;
                                }
                            }
                        }
                        // 못 찾으면 기존 방식
                        if (initializeFusion === null && clrModule !== null) {
                            initializeFusion = clrModule.findExportByName('InitializeFusion');
                        }

                        if (initializeFusion != null) {
                            const initializeFusionListener = Interceptor.attach(initializeFusion, {
                                onEnter: function (_args) {
                                    log(`.NET assembly loaded (thread #${this.threadId})`);
                                    notifyOepFound(dumpedModule, '0');
                                }
                            });
                            oepTracingListeners.push(initializeFusionListener);
                            initializeFusionHooked = true;
                        }
                    }
                }
            });
            oepTracingListeners.push(activateActivationContextListener);
            log("DEBUG: [14] ActivationContext hooked - ready");
        } else {
            log("WARNING: Could not find RtlActivateActivationContextUnsafeFast function.");
        }
    },
    notifyDumpingFinished: function () {
        // Make OEP executable again once dumping is finished
        setOepRangesProtection('rwx');
    },
    getArchitecture: function () { return Process.arch; },
    getPointerSize: function () { return Process.pointerSize; },
    getPageSize: function () { return Process.pageSize; },
    findModuleByAddress: function (address) {
        return Process.findModuleByAddress(ptr(address));
    },
    findRangeByAddress: function (address) {
        return Process.findRangeByAddress(ptr(address));
    },
    findExportByName: function (moduleName, exportName) {
        const mod = Process.findModuleByName(moduleName);
        if (mod == null) {
            return null;
        }

        return mod.findExportByName(exportName);
    },
    enumerateModules: function () {
        const modules = Process.enumerateModules();
        const moduleNames = modules.map(module => {
            return module.name;
        });
        return moduleNames;
    },
    enumerateModuleRanges: function (moduleName) {
        // [1] 유효성 검사: 이름이 없으면 빈 배열 반환
        if (!moduleName || typeof moduleName !== 'string') {
            return [];
        }

        // [2] 모듈 객체 직접 찾기
        // 전체 메모리를 뒤지는 대신, 해당 모듈 객체를 바로 가져옵니다.
        var mod = Process.findModuleByName(moduleName);

        // 모듈을 못 찾았으면 빈 배열 반환
        if (mod === null) {
            return [];
        }

        // [3] 모듈 내부 범위 조회 (Frida 내장 API 사용)
        // 'r--'는 "읽기 권한이 있는 모든 섹션"을 의미하며, 코드(.text)와 데이터(.data)를 모두 포함합니다.
        // 이 방식은 filter를 쓰지 않으므로 'not a function' 에러가 날 수 없습니다.
        return mod.enumerateRanges('r--');
    },
    enumerateExportedFunctions: function (excludedModuleName) {
        const modules = Process.enumerateModules();
        const exports = modules.reduce((acc, m) => {

            // [수정] 안전한 비교 로직
            // 1. excludedModuleName이 없거나(null/undefined)
            // 2. 문자열이 아닌 경우(boolean 등 C#에서 잘못 넘긴 경우)
            // 위 두 경우엔 제외 로직을 수행하지 않고 모든 모듈을 스캔합니다.
            let shouldInclude = true;
            if (excludedModuleName && typeof excludedModuleName === 'string') {
                if (m.name.toLowerCase() === excludedModuleName.toLowerCase()) {
                    shouldInclude = false;
                }
            }

            if (shouldInclude) {
                try {
                    m.enumerateExports().forEach(e => {
                        if (e.type == "function" && e.address) {
                            acc.push(e);
                        }
                    });
                } catch (err) {
                    // 접근 불가 모듈 무시
                }
            }
            return acc;
        }, []);
        return exports;
    },
    allocateProcessMemory: function (size, near) {
        const sizeRounded = size + (Process.pageSize - size % Process.pageSize);
        // near가 0이나 null이면 위치 지정 없이 할당
        const opts = (near) ? { near: ptr(near), maxDistance: 0xff000000 } : {};
        const addr = Memory.alloc(sizeRounded, opts);
        allocatedBuffers.push(addr)
        return addr;
    },
    queryMemoryProtection: function (address) {
        const range = Process.findRangeByAddress(ptr(address));
        if (range) {
            return range.protection;
        }
        return ""; // 범위를 못 찾으면 빈 문자열 반환
    },
    setMemoryProtection: function (address, size, protection) {
        return Memory.protect(ptr(address), size, protection);
    },
    // [중요 수정] 안전한 읽기 구현 (Try-Catch 추가)
    readProcessMemory: function (address, size) {
        //console.log("\n[JS DEBUG] >>> readProcessMemory START");
        //console.log("[JS DEBUG] Addr: " + address + ", Request Size: " + size);

        try {
            var ptrAddr = ptr(address + "");
            var intSize = parseInt(size);

            // 1. 메모리 읽기 (ArrayBuffer)
            var buffer = ptrAddr.readByteArray(intSize);

            if (buffer) {
                //console.log("[JS DEBUG] Read Success! Buffer Bytes: " + buffer.byteLength);

                // 2. 변환 (ArrayBuffer -> 일반 배열)
                var bytes = new Uint8Array(buffer);
                var result = [];
                for (var i = 0; i < bytes.length; i++) {
                    result.push(bytes[i]);
                }

                //console.log("[JS DEBUG] Converted to Array. Sending " + result.length + " items.");
                return result;
            } else {
                //console.log("[JS DEBUG] Read Failed (buffer is null). Returning empty array.");
                return [];
            }

        } catch (e) {
            console.log("[JS DEBUG] EXCEPTION: " + e.message);
            return [];
        } finally {
            //console.log("[JS DEBUG] <<< readProcessMemory END\n");
        }
    },
    // [중요 수정] 안전한 쓰기 구현
    writeProcessMemory: function (address, bytes) {
        try {
            return Memory.writeByteArray(ptr(address), bytes);
        } catch (e) {
            return false; // 실패 시 false 반환 등 처리 가능 (C# 반환 타입에 따라 다름)
        }
    }
};