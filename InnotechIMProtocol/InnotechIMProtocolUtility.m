//
//  InnotechIMProtocolUtility.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/12/11.
//  Copyright © 2019 jocer. All rights reserved.
//

#import "InnotechIMProtocolUtility.h"

@implementation InnotechIMProtocolUtility
+ (NSData *) bigIntToByte:(int) value withLen:(int) len
{
  if(len == 1){
    Byte b1 = value & 0xff;
    Byte byte[] = {b1};
    NSData *data = [NSData dataWithBytes:byte length:sizeof(byte)];
    return data;
  }else if(len == 2){
    Byte b1 = value & 0xff;
    Byte b2 = (value>>8) & 0xff;
    Byte byte[] = {b2,b1};
    NSData *data = [NSData dataWithBytes:byte length:sizeof(byte)];
    return data;
  }else{
    Byte b1 = value & 0xff;
    Byte b2 = (value>>8) & 0xff;
    Byte b3 = (value>>16) & 0xff;
    Byte b4 = (value>>24) & 0xff;
    Byte byte[] = {b4,b3,b2,b1};
    NSData *data = [NSData dataWithBytes:byte length:sizeof(byte)];
    return data;
  }
}

+ (NSData *)bigLongToByte:(long)value {
  Byte b1 = value & 0xff;
  Byte b2 = (value>>8) & 0xff;
  Byte b3 = (value>>16) & 0xff;
  Byte b4 = (value>>24) & 0xff;
  Byte b5 = (value>>32) & 0xff;
  Byte b6 = (value>>40) & 0xff;
  Byte b7 = (value>>48) & 0xff;
  Byte b8 = (value>>56) & 0xff;
  Byte bytes[] = {b8,b7,b6,b5,b4,b3,b2,b1};
  NSData *data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
  return data;
}

+ (int) bigBytesToInt:(Byte *) bytes
{
  int addr = 0;
  addr = bytes[0] & 0xFF;
  addr = (addr << 8) | (bytes[1] & 0xff);
  addr = (addr << 8) | (bytes[2] & 0xff);
  addr = (addr << 8) | (bytes[3] & 0xff);
  return addr;
}

+ (long)bigBytesToLong:(Byte *)bytes {
  long value = 0;
  value = bytes[0] & 0xff;
  for (int i = 1; i < 8; i++) {
    value = (value << 8) | (bytes[i] & 0xff);
  }
  return value;
}

+ (int) getLenByData:(Byte *) data {
  Byte *bytes = malloc(sizeof(Byte)*(4));
  for (int i = 0; i < 4; i ++) {
    bytes[i] = data[i];
  }
  return [InnotechIMProtocolUtility bigBytesToInt:bytes] - 12;
}
+ (BOOL)getGzippedStatus:(Byte *)data {
  Byte byte = data[12];
  BOOL gzipped = byte & 0xFF;
  return gzipped;
}
+ (int) getCommandByData:(Byte *) data {
  Byte *bytes = malloc(sizeof(Byte)*(4));
  bytes[0] = 0;
  for (int i = 1; i < 4; i ++) {
    bytes[i] = data[i + 12];
  }
  return [InnotechIMProtocolUtility bigBytesToInt:bytes];
}

+ (NSData *)getRequestIDData:(NSData *)data {
  NSData *requestIDData = [data subdataWithRange:NSMakeRange(4, 8)];
  return requestIDData;
}

+(NSDictionary *) converToDictionary:(NSString *)jsonStr {
  if (jsonStr == nil) {
    return nil;
  }
  NSData *jsonData = [jsonStr dataUsingEncoding:NSUTF8StringEncoding];
  NSError *err;
  NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                      options:NSJSONReadingMutableContainers
                                                        error:&err];
  if(err) {
    NSLog(@"json解析失败：%@ \n json string： %@",err, jsonStr);
    return nil;
  }
  return dic;
}

+(NSString *)convertToJsonData:(NSDictionary *)dict {
  
  NSError *error;
  
  NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&error];
  
  NSString *jsonString = @"";
  
  if (!jsonData) {
    
    NSLog(@"json解析失败：%@ \n json dict： %@",error,dict);
    
  }else{
    jsonString = [[NSString alloc]initWithData:jsonData encoding:NSUTF8StringEncoding];
    
  }
  return jsonString;
  
}
@end
