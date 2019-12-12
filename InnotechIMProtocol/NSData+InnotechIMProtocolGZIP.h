//
//  InnotechIMProtocolManager.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/12/11.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (InnotechIMProtocolGZIP)

- (nullable NSData *)gzippedDataWithCompressionLevel:(float)level;
- (nullable NSData *)gzippedData;
- (nullable NSData *)gunzippedData;
- (BOOL)isGzippedData;

@end
