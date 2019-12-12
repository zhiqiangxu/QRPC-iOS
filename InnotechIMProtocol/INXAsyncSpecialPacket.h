//
//  INXAsyncSpecialPacket.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/**
 * INXAsyncSpecialPacket包含针对读/写队列中的中断的特殊指令。
 * 这个类可能被修改，以支持在未来更多的TLS。.
 **/
@interface INXAsyncSpecialPacket : NSObject
{
@public
    NSDictionary *tlsSettings;
}
- (id)initWithTLSSettings:(NSDictionary *)settings;
@end

NS_ASSUME_NONNULL_END
