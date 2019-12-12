//
//  InnotechIMProtocolManager.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/12/11.
//  Copyright © 2019 jocer. All rights reserved.
//

#import "InnotechIMProtocolManager.h"
#import "INXAsyncSocket.h"
#import "INXAsyncSocketDelegate.h"
#import "INXSCommandInfo.h"
#import "InnotechIMProtocolUtility.h"
#import "NSData+InnotechIMProtocolGZIP.h"

static NSUInteger SOCKET_HEADER_LENGTH          = 16;
static NSInteger SOCKET_HEADER_TAG              = -1;

static NSInteger const kInnotechIMProtocolSendCmdError = 10001;

static NSErrorDomain const kInnotechIMProtocolErrorDomain = @"kInnotechIMProtocolErrorDomain";

@interface InnotechIMProtocolManager () <INXAsyncSocketDelegate>
@property (nonatomic, strong) INXAsyncSocket *socket;
@property (nonatomic, strong) NSMutableDictionary <NSData *, INXSCommandInfo *>*ongoingCmdInfos;
@property (nonatomic, weak) id <InnotechIMProtocol> delegate;
@property (nonatomic, weak) dispatch_queue_t sdQueue;
@end

@implementation InnotechIMProtocolManager

- (instancetype)init {
  self = [self initWithDelegate:nil delegateQueue:dispatch_get_main_queue()];
  return self;
}

- (instancetype)initWithDelegate:(id<InnotechIMProtocol>)delegate delegateQueue:(dispatch_queue_t)queue {
  self = [super init];
  if (self) {
    self.sdQueue = queue;
    self.socket = [[INXAsyncSocket alloc] initWithDelegate:self delegateQueue:queue];
  }
  return self;
}

- (BOOL)connectToHost:(NSString *)host onPort:(uint16_t)port error:(NSError * _Nullable __autoreleasing *)errPtr {
  if (!self.socket.delegate) {
    [self.socket setDelegate:self];
  }
  if (!self.socket.delegateQueue) {
    [self.socket setDelegateQueue:self.sdQueue];
  }
  return [self.socket connectToHost:host onPort:port error:errPtr];
}

- (BOOL)isConnected {
  return self.socket.isConnected;
}

- (BOOL)isDisconnected {
  return self.socket.isDisconnected;
}

- (void)disconnect {
  if ([self isConnected]) {
    [self.socket setDelegate:nil delegateQueue:nil];
    [self.socket disconnect];
  }
  if (self.ongoingCmdInfos.count > 0) {
    [self.ongoingCmdInfos enumerateKeysAndObjectsUsingBlock:^(NSData * _Nonnull key, INXSCommandInfo * _Nonnull obj, BOOL * _Nonnull stop) {
      NSError *error = [NSError errorWithDomain:kInnotechIMProtocolErrorDomain code:kInnotechIMProtocolSendCmdError userInfo:@{NSLocalizedDescriptionKey:@(obj.cmd)}];
      if (obj.sendCompeletionBlock) obj.sendCompeletionBlock(nil, error);
      if (obj.completion) obj.completion(nil, error);
    }];
    [self.ongoingCmdInfos removeAllObjects];
  }
}

- (INXSCommandInfo *)sendDataByCMD:(int32_t)cmd andParams:(NSString *)params sendProgress:(InnotechIMProtocolProgressBlock)sendProgress sendCompeletion:(InnotechIMProtocolCompeletionBlock)sendCompeletion receiveHandler:(InnotechIMProtocolReceiveHandler)receiveHandler completion:(InnotechIMProtocolCompeletionBlock)completion {
  NSData *pData = [params dataUsingEncoding:NSUTF8StringEncoding];
  NSData *len = [InnotechIMProtocolUtility bigIntToByte:pData?(int)pData.length+12:12 withLen:4];
  Byte request[8] = {arc4random_uniform(256),
    arc4random_uniform(256) ,
    arc4random_uniform(256) ,
    arc4random_uniform(256) ,
    arc4random_uniform(256) ,
    arc4random_uniform(256) ,
    arc4random_uniform(256) ,
    arc4random_uniform(256)};
  NSData *requestId = [NSData dataWithBytes:request length:sizeof(request)];
  long requestIdLong = [InnotechIMProtocolUtility bigBytesToLong:request];
  NSData *command = [InnotechIMProtocolUtility bigIntToByte:cmd withLen:4];
  NSMutableData *data = [NSMutableData dataWithLength:0];
  [data appendData:len];
  [data appendData:requestId];
  [data appendData:command];
  [data appendData:pData];
  INXSCommandInfo *info = [INXSCommandInfo new];
  info.length = len.length;
  info.jsonData = pData;
  info.requestID = requestId;;
  info.cmd = cmd;
  info.sendProgressBlock = sendProgress;
  info.sendCompeletionBlock = sendCompeletion;
  info.receiveHandler = receiveHandler;
  InnotechIMProtocolCompeletionBlock copied = [completion copy];
  InnotechIMProtocolCompeletionBlock innetCompletion = ^(id data, NSError *error) {
    if (copied) {
      copied(data, error);
    }
    [self __clearCurrentOngoingCmdInfo:info];
    
  };
  info.completion = innetCompletion;
  [self.socket writeData:data withTimeout:-1 tag:requestIdLong];
  return info;
}

#pragma mark - Private Methods
- (void)callBackSafe:(dispatch_block_t)block {
  if (dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL) == dispatch_queue_get_label(self.socket.delegateQueue)) {
    block();
  } else {
    dispatch_async(self.socket.delegateQueue, ^{
      block();
    });
  }
}
- (void)__clearCurrentOngoingCmdInfo:(INXSCommandInfo *)cmdInfo {
  dispatch_block_t clear = ^{
    if (cmdInfo && cmdInfo.requestID) {
      self.ongoingCmdInfos[cmdInfo.requestID] = nil;
    }
  };
  if (dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL) == dispatch_queue_get_label(dispatch_get_main_queue())) {
    clear();
  } else {
    dispatch_async(dispatch_get_main_queue(), ^{
      clear();
    });
  }
}
#pragma mark - INXAsyncSocketDelegate
- (void)socket:(INXAsyncSocket *)sock didWriteDataWithTag:(long)tag {
  NSData *writeId = [InnotechIMProtocolUtility bigLongToByte:tag];
  INXSCommandInfo *info = self.ongoingCmdInfos[writeId];
  InnotechIMProtocolProgressBlock progress = info.sendProgressBlock;
  InnotechIMProtocolCompeletionBlock compeletion = info.sendCompeletionBlock;
  [self callBackSafe:^{
    if (progress) {
      progress(1.f);
    }
    if (compeletion) {
      compeletion(nil, nil);
    }
  }];
}
- (void)socket:(INXAsyncSocket *)sock didWritePartialDataOfLength:(NSUInteger)partialLength tag:(long)tag {
  long currentTag;
  float value = [sock progressOfWriteReturningTag:&currentTag bytesDone:nil total:nil];
  NSData *writeId = [InnotechIMProtocolUtility bigLongToByte:currentTag];
  INXSCommandInfo *info = self.ongoingCmdInfos[writeId];
  InnotechIMProtocolProgressBlock progress = info.sendProgressBlock;
  [self callBackSafe:^{
    if (progress) {
      progress(value);
    }
  }];
}
- (void)socket:(INXAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
  [sock readDataToLength:SOCKET_HEADER_LENGTH withTimeout:-1 tag:SOCKET_HEADER_TAG];
  if (self.delegate && [self.delegate respondsToSelector:@selector(protocolManager:didConnectToHost:port:)]) {
    [self callBackSafe:^{
      [self.delegate protocolManager:self didConnectToHost:host port:port];
    }];
  }
}
- (void)socket:(INXAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
  if (tag == SOCKET_HEADER_TAG) {
    Byte * byte = (Byte *)[data bytes];
    NSData *requestID = [InnotechIMProtocolUtility getRequestIDData:data];
    INXSCommandInfo *info = self.ongoingCmdInfos[requestID];
    if (info) {
      info.length = [InnotechIMProtocolUtility getLenByData:byte];
      info.cmd = [InnotechIMProtocolUtility getCommandByData:byte];
      info.isGzipped = [InnotechIMProtocolUtility getGzippedStatus:byte];
    } else {
      info.length = [InnotechIMProtocolUtility getLenByData:byte];
      info.cmd = [InnotechIMProtocolUtility getCommandByData:byte];
      info.isGzipped = [InnotechIMProtocolUtility getGzippedStatus:byte];
      self.ongoingCmdInfos[requestID] = info;
    }
    long requestIDInteger = [InnotechIMProtocolUtility bigBytesToLong:(Byte *)requestID.bytes];
    [sock readDataToLength:info.length withTimeout:-1 tag:requestIDInteger];
  } else {
    NSData *requestID = [InnotechIMProtocolUtility bigLongToByte:tag];
    if (requestID) {
      INXSCommandInfo *info = self.ongoingCmdInfos[requestID];
      if (info.isGzipped || data.isGzippedData) {
        info.jsonData = [data gunzippedData];
      } else {
        info.jsonData = data;
      }
      if (info.receiveHandler) {
        [self callBackSafe:^{
          info.receiveHandler(info);
        }];
      }
      if (self.delegate && [self.delegate respondsToSelector:@selector(protocolManager:didReadData:)]) {
        [self callBackSafe:^{
          [self.delegate protocolManager:self didReadData:info];
        }];
      }
      
    }
    [sock readDataToLength:SOCKET_HEADER_LENGTH withTimeout:-1 tag:SOCKET_HEADER_TAG];
  }
}

- (void)socket:(INXAsyncSocket *)sock didReadPartialDataOfLength:(NSUInteger)partialLength tag:(long)tag {
  
}

- (void)socket:(INXAsyncSocket *)sock didReceiveTrust:(SecTrustRef)trust completionHandler:(void (^)(BOOL))completionHandler {
  completionHandler(YES);
}

- (void)socketDidDisconnect:(INXAsyncSocket *)sock withError:(nullable NSError *)err {
  if (self.delegate && [self.delegate respondsToSelector:@selector(protocolManagerDidDisconnect:withError:)]) {
    [self callBackSafe:^{
      [self.delegate protocolManagerDidDisconnect:self withError:err];
    }];
  }
}

#pragma mark - Lazy Load
- (NSMutableDictionary<NSData *,INXSCommandInfo *> *)ongoingCmdInfos {
  if (!_ongoingCmdInfos) {
    _ongoingCmdInfos = [NSMutableDictionary dictionary];
  }
  return _ongoingCmdInfos;
}
@end
