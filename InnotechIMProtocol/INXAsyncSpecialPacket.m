//
//  INXAsyncSpecialPacket.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import "INXAsyncSpecialPacket.h"

@implementation INXAsyncSpecialPacket
- (id)initWithTLSSettings:(NSDictionary *)settings
{
    if((self = [super init]))
    {
        tlsSettings = [settings copy];
    }
    return self;
}
@end
