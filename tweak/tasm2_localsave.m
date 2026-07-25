//
//  TASM2 local save — injected dylib (LiveContainer tweak)
//
//  Runtime plumbing only, at this stage: locate the game image, translate the
//  static addresses used in the analysis notes into runtime addresses, and get
//  control at the moments that matter (launch, background, terminate, timer).
//  The save/load calls themselves land on top of this once the disassembly has
//  settled which functions to call.
//
//  Why this shape:
//   - LiveContainer turns the game from MH_EXECUTE into MH_DYLIB and dlopen()s
//     it, so the game is *not* the main image. It has to be found by name.
//   - Nothing here writes to executable memory. Calling the game's own
//     functions through a pointer needs no entitlement; inline hooking would.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <string.h>

// The arm64 slice is linked at this address; every address in
// LOCAL_SAVE_DESIGN.md is expressed in that space.
#define TASM2_LINK_BASE 0x100000000ULL

static intptr_t g_slide = 0;
static BOOL g_found = NO;

#pragma mark - logging

static NSString *log_path(void) {
    static NSString *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *d = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES);
        p = [d.firstObject stringByAppendingPathComponent:@"tasm2_localsave.log"];
    });
    return p;
}

static void tlog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"[tasm2] %@", msg);

    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                      [NSDate date].description, msg];
    NSString *path = log_path();
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (f) {
        fputs(line.UTF8String, f);
        fclose(f);
    }
}

#pragma mark - locating the game image

// The game binary as loaded by LiveContainer: same file name, MH_DYLIB.
static BOOL image_is_game(const char *name) {
    return name && strstr(name, "AmazingSpiderMan2") != NULL;
}

static void adopt_image(const struct mach_header *mh, intptr_t slide,
                        const char *name) {
    if (g_found) return;
    g_slide = slide;
    g_found = YES;
    tlog(@"game image found: %s", name);
    tlog(@"  header=%p slide=%#lx  link base %#llx -> runtime %#llx",
         mh, (unsigned long)slide, TASM2_LINK_BASE,
         (unsigned long long)(TASM2_LINK_BASE + slide));
}

static void image_added(const struct mach_header *mh, intptr_t slide) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        if (_dyld_get_image_header(i) == mh) {
            const char *n = _dyld_get_image_name(i);
            if (image_is_game(n)) adopt_image(mh, slide, n);
            return;
        }
    }
}

static BOOL scan_loaded_images(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (image_is_game(n)) {
            adopt_image(_dyld_get_image_header(i),
                        _dyld_get_image_vmaddr_slide(i), n);
            return YES;
        }
    }
    return NO;
}

// Translate an address from the analysis notes into a callable pointer.
static void *rt(uint64_t link_addr) {
    if (!g_found) return NULL;
    return (void *)(uintptr_t)(link_addr + (uint64_t)g_slide);
}

#pragma mark - lifecycle

static void on_save_moment(NSString *why) {
    if (!g_found) {
        tlog(@"save moment (%@) but the game image is not located yet", why);
        return;
    }
    tlog(@"save moment: %@", why);
    // TODO: call the game's own serialisation here.
}

static void on_load_moment(void) {
    if (!g_found) return;
    tlog(@"load moment");
    // TODO: call the game's own deserialisation here.
}

static void install_observers(void) {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) { on_save_moment(@"background"); }];

    [nc addObserverForName:UIApplicationWillTerminateNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) { on_save_moment(@"terminate"); }];

    [nc addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) { tlog(@"active"); }];
}

#pragma mark - entry point

__attribute__((constructor))
static void tasm2_localsave_init(void) {
    tlog(@"tweak loaded (build %s %s)", __DATE__, __TIME__);

    if (!scan_loaded_images()) {
        // The guest may be dlopen()ed after the tweak; catch it when it lands.
        _dyld_register_func_for_add_image(image_added);
        tlog(@"game image not loaded yet, waiting for it");
    }

    install_observers();

    // Give the engine time to build its managers before touching anything.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!g_found) scan_loaded_images();
        on_load_moment();
    });
}
