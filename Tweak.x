// Minimal test - just create a file to prove injection works
#import <Foundation/Foundation.h>

%ctor {
    [@"tweak loaded OK" writeToFile:@"/var/tmp/ps_test.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"[PSBypass] LOADED into %@", [[NSBundle mainBundle] bundleIdentifier]);
}
