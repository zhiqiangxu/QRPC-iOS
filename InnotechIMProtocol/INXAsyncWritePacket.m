//
//  INXAsyncWritePacket.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import "INXAsyncWritePacket.h"

@implementation INXAsyncWritePacket
- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i
{
    if((self = [super init]))
    {
        buffer = d; // Retain not copy. For performance as documented in header file.
        bytesDone = 0;
        timeout = t;
        tag = i;
    }
    return self;
}

- (void)dealloc {
#if __has_feature(objc_arc)
#else
    [buffer release];
    [super dealloc];
#endif
}
@end
