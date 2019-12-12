//
//  InnotechIMProtocolUtility.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/12/11.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface InnotechIMProtocolUtility : NSObject
+ (NSData *) bigIntToByte:(int) value withLen:(int) len;
+ (NSData *) bigLongToByte:(long) value;
+ (int)bigBytesToInt:(Byte *) bytes;
+ (long)bigBytesToLong:(Byte *) bytes;
+ (int)getLenByData:(Byte *) data;
+ (BOOL)getGzippedStatus:(Byte *)data;
+ (int)getCommandByData:(Byte *) data;
+ (NSData *)getRequestIDData:(NSData *)data;
+ (NSString *)getJsonByData:(NSData *) data;

+(NSString *)convertToJsonData:(NSDictionary *)dict;
+ (NSDictionary *) converToDictionary:(NSString *)jsonStr;
@end

NS_ASSUME_NONNULL_END
