




#import <Foundation/Foundation.h>

@interface Foo : NSObject {
}

@end

@implementation Foo

- (void) doCrash {
	char * ptr = (char*)0x44444444;
	ptr[0] = 0;
}
@end



int main() {
	Foo * foo = [[Foo alloc] init];
	[foo doCrash];
}