// Tier C iOS JavaScriptCore harness source. Compile inside the app target.
// RA-LAN-005: JIT options must be set before the first JavaScriptCore context
// is initialized. This file demonstrates the required ordering for the
// on-device JavaScriptCore.framework embed.

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <JavaScriptCore/JavaScriptCore.h>

static void *g_jsc_library = NULL;
static BOOL g_jsc_initialized = NO;

void RASetJitOptionsBeforeContextInit(void) {
    // Do not create JSGlobalContext before these setenv calls.
    setenv("JSC_useConcurrentJIT", "1", 1);
    setenv("JSC_useJIT", "1", 1);
}

BOOL RAInitializeJavaScriptCore(void) {
    if (g_jsc_initialized) {
        return YES;
    }
    // Prefer the private-framework dlopen path required by Tier C. If the
    // framework is already linked at load time, dlopen returns the same image.
    g_jsc_library = dlopen("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore", RTLD_NOW);
    if (g_jsc_library == NULL) {
        // App-embedded JavaScriptCore is also acceptable; fall back to the
        // public framework path so unit/device harnesses can run.
        g_jsc_library = dlopen("@executable_path/Frameworks/JavaScriptCore.framework/JavaScriptCore", RTLD_NOW);
    }
    if (g_jsc_library == NULL) {
        return NO;
    }
    RASetJitOptionsBeforeContextInit();
    g_jsc_initialized = YES;
    return YES;
}

JSContext *RACreateContext(void) {
    if (!g_jsc_initialized && !RAInitializeJavaScriptCore()) {
        return NULL;
    }
    JSGlobalContextRef global = JSGlobalContextCreate(NULL);
    if (global == NULL) {
        return NULL;
    }
    return [JSContext contextWithJSGlobalContextRef:global];
}

JSValue *RAEvalString(JSContext *ctx, NSString *script) {
    if (ctx == nil || script == nil) {
        return nil;
    }
    return [ctx evaluateScript:script];
}
