//
//  INXAsyncSocket.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/5/22.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>
#import <dispatch/dispatch.h>
#import <Availability.h>

#include <sys/socket.h> // AF_INET, AF_INET6

@class INXAsyncReadPacket;
@class INXAsyncWritePacket;
@class INXAsyncSocketPreBuffer;
@protocol INXAsyncSocketDelegate;

NS_ASSUME_NONNULL_BEGIN

extern NSString *const INXAsyncSocketException;
extern NSString *const INXAsyncSocketErrorDomain;

extern NSString *const INXAsyncSocketQueueName;
extern NSString *const INXAsyncSocketThreadName;

extern NSString *const INXAsyncSocketManuallyEvaluateTrust;
#if TARGET_OS_IPHONE
extern NSString *const INXAsyncSocketUseCFStreamForTLS;
#endif
#define INXAsyncSocketSSLPeerName     (NSString *)kCFStreamSSLPeerName
#define INXAsyncSocketSSLCertificates (NSString *)kCFStreamSSLCertificates
#define INXAsyncSocketSSLIsServer     (NSString *)kCFStreamSSLIsServer
extern NSString *const INXAsyncSocketSSLPeerID;
extern NSString *const INXAsyncSocketSSLProtocolVersionMin;
extern NSString *const INXAsyncSocketSSLProtocolVersionMax;
extern NSString *const INXAsyncSocketSSLSessionOptionFalseStart;
extern NSString *const INXAsyncSocketSSLSessionOptionSendOneByteRecord;
extern NSString *const INXAsyncSocketSSLCipherSuites;
#if !TARGET_OS_IPHONE
extern NSString *const INXAsyncSocketSSLDiffieHellmanParameters;
#endif

#define INXAsyncSocketLoggingContext 65535

typedef NS_ENUM(NSInteger, INXAsyncSocketError) {
    INXAsyncSocketNoError = 0,           // Never used
    INXAsyncSocketBadConfigError,        // 错误的配置
    INXAsyncSocketBadParamError,         // 传递无效参数
    INXAsyncSocketConnectTimeoutError,   // 连接操作超时
    INXAsyncSocketReadTimeoutError,      // 读取操作超时
    INXAsyncSocketWriteTimeoutError,     // 写操作超时
    INXAsyncSocketReadMaxedOutError,     // 未完成时达到设置的最大长度
    INXAsyncSocketClosedError,           // 远程对等点关闭连接
    INXAsyncSocketOtherError,            // 详见userInfo
};

@interface INXAsyncSocket : NSObject

/**
 * 在给定的委托队列中执行所有的委托回调，并为并发处理提供简单的线程安全。
 * 给定的`socketQueue`必须为非并行队列，若传空内部将使用默认串行队列
 * 给定的`socketQueue`可以和`delegateQueue`一致
 * 若给定的`socketQueue`具有已配置的`targetQueue`，请参阅`markSocketQueueTargetQueue`方法讨论
 **/
- (instancetype)init;
- (instancetype)initWithSocketQueue:(nullable dispatch_queue_t)sq;
- (instancetype)initWithDelegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq;
- (instancetype)initWithDelegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq socketQueue:(nullable dispatch_queue_t)sq;

/**
 * 从已连接BSDsocket文件描述符创建INXAsyncSocket
 **/
+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD socketQueue:(nullable dispatch_queue_t)sq error:(NSError**)error;

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq error:(NSError**)error;

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq socketQueue:(nullable dispatch_queue_t)sq error:(NSError **)error;

#pragma mark Configuration

@property (atomic, weak, readwrite, nullable) id<INXAsyncSocketDelegate> delegate;
#if OS_OBJECT_USE_OBJC
@property (atomic, strong, readwrite, nullable) dispatch_queue_t delegateQueue;
#else
@property (atomic, assign, readwrite, nullable) dispatch_queue_t delegateQueue;
#endif

- (void)getDelegate:(id<INXAsyncSocketDelegate> __nullable * __nullable)delegatePtr delegateQueue:(dispatch_queue_t __nullable * __nullable)delegateQueuePtr;
- (void)setDelegate:(nullable id<INXAsyncSocketDelegate>)delegate delegateQueue:(nullable dispatch_queue_t)delegateQueue;

/**
 * 在`delegate`的`dealloc`方法内置空`INXAsyncSocket`，需要同步操作
 **/
- (void)synchronouslySetDelegate:(nullable id<INXAsyncSocketDelegate>)delegate;
- (void)synchronouslySetDelegateQueue:(nullable dispatch_queue_t)delegateQueue;
- (void)synchronouslySetDelegate:(nullable id<INXAsyncSocketDelegate>)delegate delegateQueue:(nullable dispatch_queue_t)delegateQueue;

/**
 * 默认情况下IPv4和IPv6都是开启状态，不配置的情况下将根据DNS的返回结果选择使用IPv4/IPv6，若同时存在将选择首选协议，默认情况下首选协议是IPv4
 **/

@property (atomic, assign, readwrite, getter=isIPv4Enabled) BOOL IPv4Enabled;
@property (atomic, assign, readwrite, getter=isIPv6Enabled) BOOL IPv6Enabled;

@property (atomic, assign, readwrite, getter=isIPv4PreferredOverIPv6) BOOL IPv4PreferredOverIPv6;

/**
 * 使用`Happy Eyeballs(RFC 6555)`连接IPv4和IPv6时的延迟
 * 默认300ms
 **/
@property (atomic, assign, readwrite) NSTimeInterval alternateAddressDelay;

/**
 * 允许将socket与用户数据进行关联，内部任何地方都不会使用此数据
 **/
@property (atomic, strong, readwrite, nullable) id userData;

#pragma mark Accepting

/**
 * 开始监听/接收给定端口上的连接，接受成功后将会有一个新的`INXAsyncSocket`实例被生成来处理它，
 * 接受成功会调用`didAcceptNewSocket: delegate`回调
 * 内部将监听所有可用接口(Wifi/3G)
 **/
- (BOOL)acceptOnPort:(uint16_t)port error:(NSError **)errPtr;

/**
 * 指定接受哪些连接接口
 * 'localhost'/'loopback'只接受本地连接,'192.168.4.34'按IP地址连接,'en1'/'lo0'根据名称连接,e.g.
 **/
- (BOOL)acceptOnInterface:(nullable NSString *)interface port:(uint16_t)port error:(NSError **)errPtr;

/**
 * 开始侦听和接受给定url上unix域上的连接。
 **/
- (BOOL)acceptOnUrl:(NSURL *)url error:(NSError **)errPtr;

#pragma mark Connecting

/**
 * 连接到给定的主机和端口。
 * 使用默认接口，没有超时
 **/
- (BOOL)connectToHost:(NSString *)host onPort:(uint16_t)port error:(NSError **)errPtr;

/**
 * 给定超时时间进行连接
 **/
- (BOOL)connectToHost:(NSString *)host
               onPort:(uint16_t)port
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr;

/**
 * 通过可选接口，使用可选超时连接到给定的主机和端口。
 * host可以是"example.com"/"192.168.0.2"/"localhost"/"loopback"等方式
 *
 * 接口可以是一个名称(例如。“en1”或“lo0”或对应的IP地址(例如:“192.168.4.35”)。
 * 该接口还可以用于指定本地端口(参见下面)。
 *
 * 超时时间设置为负数表示为不设置超时时间.
 *
 * 连接发生错误，将会为`&errPtr`赋值具体错误信息
 *
 *
 * 如果没有检测到错误，此方法将启动后台连接操作并立即返回YES。
 * 委托回调用于通知您socket何时连接，或者主机是否不可用。
 *
 * 由于该类支持排队读取和写入，您可以立即开始读取和/或写入。连接成功后将按顺序处理读取写入。
 *
 * `interface`可以是"en1:8082"/"192.168.4.35:2424"/":8082"
 * 但99.99%的情况下是不需要为server提供本地接口的。
 **/
- (BOOL)connectToHost:(NSString *)host
               onPort:(uint16_t)port
         viaInterface:(nullable NSString *)interface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr;

/**
 * 根据`sockaddr`结构体所生成的NSData对象连接到给定地址(e.g. [NSNetService address])
 * 具体sockaddr结构体与NSData的转换操作请移步google。
 * 这个方法将会调用`connectToAdd`
 **/
- (BOOL)connectToAddress:(NSData *)remoteAddr error:(NSError **)errPtr;

/**
 * 设置可选超时时间
 **/
- (BOOL)connectToAddress:(NSData *)remoteAddr withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr;

/**
 * 同`- (BOOL)connectToHost:onPort:viaInterface:withTimeout:error:`
 **/
- (BOOL)connectToAddress:(NSData *)remoteAddr
            viaInterface:(nullable NSString *)interface
             withTimeout:(NSTimeInterval)timeout
                   error:(NSError **)errPtr;
/**
 * 使用指定的超时，以给定的url连接到unix域socket。
 */
- (BOOL)connectToUrl:(NSURL *)url withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr;

#pragma mark Disconnecting

/**
 * 在`socketQueue`同步断开连接，放弃未完成的所有读写任务，之后在`delegateQueue`异步回调`socketDidDisconnect:withError:`
 * 释放`socket`的推荐做法：
 * [asyncSocket setDelegate:nil];
 * [asyncSocket disconnect];
 * [asyncSocket release];
 *
 * 若打算断开连接后立即开始尝试重连，建议：
 * [asyncSocket setDelegate:nil];
 * [asyncSocket disconnect];
 * [asyncSocket setDelegate:self];
 * [asyncSocket connect...];
 **/
- (void)disconnect;

/**
 * 所有读操作完成后断开连接（直至重新连接否则所有的写操作无效）
 **/
- (void)disconnectAfterReading;

/**
 * 所有写操作完成后断开连接（直至重新连接否则所有的读操作无效）
 **/
- (void)disconnectAfterWriting;

/**
 * 所有的读写操作完成后断开连接（直至重新连接否则所有的读写操作无效）
 **/
- (void)disconnectAfterReadingAndWriting;

#pragma mark Diagnostics

/**
 * 同一个`INXAsyncSocket`可以进行多次连接/断开连接
 * 但正在连接中的socket不能进行连接/断开连接
 **/
@property (atomic, readonly) BOOL isDisconnected;
@property (atomic, readonly) BOOL isConnected;

/**
 * `INXAsyncSocket`所连接的IP地址及端口（nil/0如果未连接）
 **/
@property (atomic, readonly, nullable) NSString *connectedHost;
@property (atomic, readonly) uint16_t  connectedPort;
@property (atomic, readonly, nullable) NSURL    *connectedUrl;

@property (atomic, readonly, nullable) NSString *localHost;
@property (atomic, readonly) uint16_t  localPort;

/**
 * `INXAsyncSocket`所连接的IP地址及端口(同上)的`sockaddr`结构体，
 **/
@property (atomic, readonly, nullable) NSData *connectedAddress;
@property (atomic, readonly, nullable) NSData *localAddress;

/**
 * 当前`INXAsyncSocket`的IP协议（一个接收方的socket可能同时都包含）
 **/
@property (atomic, readonly) BOOL isIPv4;
@property (atomic, readonly) BOOL isIPv6;

/**
 * 是否通过`SSL/TLS`保护（详见`startTLS`方法）
 **/
@property (atomic, readonly) BOOL isSecure;

#pragma mark Reading

// 读写数据操作是在`socketQueue`异步进行的不会阻塞线程
// 读写数据操作完成后将会在`delegateQueue`分别回调`socket:didReadData:withTag:``socket:didWriteDataWithTag:`
//
// 设置负数表示不设置超时时间
// 若读写操作出现超时将会在`delegateQueue`回调`socket:shouldTimeout...`方法
// 超时后将会在`delegateQueue`回调`didDisconnectWithError`方法
//
// `tag`可以被用作数组索引、步骤号、状态id、指针等。

/**
 * 读取socket上可用的第一个字节。
 **/
- (void)readDataWithTimeout:(NSTimeInterval)timeout tag:(long)tag;

/**
 * 读取数据时将会从一个给定的bufferOffset追加到给定的buffer中。
 * 若bufferOffset大于给定的buffer已有的总长度将会立即return，并不再回调对应的代理方法`socket:didReadData:withTag:`
 * 若buffer传空，内部将会创建一个默认的buffer
 * buffer将会在必要时自动增加尺寸
 *
 * 如果传入一个自定义的buffer，请不要socket使用它时以任何方式改变它
 * 在随后的回调`socket:didReadData:withTag:`中读取完毕的数据其实是
 * 通过`[NSData dataWithBytesNoCopy:length:freeWhenDone:NO].`从给定的buffer拿到的子集。
 **/
- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(nullable NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                        tag:(long)tag;

/**
 * 设置读取数据的最大长度，其余同上
 **/
- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(nullable NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                  maxLength:(NSUInteger)length
                        tag:(long)tag;

/**
 * 读取至指定长度，若长度为0此方法将不会有任何效果，且不会回调对应的代理方法
 **/
- (void)readDataToLength:(NSUInteger)length withTimeout:(NSTimeInterval)timeout tag:(long)tag;

/**
 * 读取至指定长度到一个给定buffer的给定offset
 **/
- (void)readDataToLength:(NSUInteger)length
             withTimeout:(NSTimeInterval)timeout
                  buffer:(nullable NSMutableData *)buffer
            bufferOffset:(NSUInteger)offset
                     tag:(long)tag;

/**
 * 读取至给定的`data`，一般该`data`用作分隔符（若传入nil或0长度的data分隔符，此方法将会直接return并不会回调代理方法）
 * 谨慎使用分隔符，避免数据流中包含给定的分隔符导致数据错误
 * 给定的分隔符在被使用过程中不要做改变，因为内部将retain此分隔符而非copy
 **/
- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag;

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(nullable NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
                   tag:(long)tag;

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag;

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(nullable NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
             maxLength:(NSUInteger)length
                   tag:(long)tag;

/**
 * 返回当前读取的进度，从0.0到1.0，如果没有当前读取，返回NaN(使用isnan()检查)。
 * 如果参数“tag”、“done”和“total”不为空，则填充它们。
 **/
- (float)progressOfReadReturningTag:(nullable long *)tagPtr bytesDone:(nullable NSUInteger *)donePtr total:(nullable NSUInteger *)totalPtr;

#pragma mark Writing

/**
 * 出于性能原因，写数据时内部不会copy数据而只会retain
 * 如果需要从一个不可变缓存区写入传入的可变数据，请将此数据copy后再传入
 **/
- (void)writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag;

/**
 * 写入数据进度
 **/
- (float)progressOfWriteReturningTag:(nullable long *)tagPtr bytesDone:(nullable NSUInteger *)donePtr total:(nullable NSUInteger *)totalPtr;

#pragma mark Security

/**
 * 任何时候都可以调用，并将于所有挂起的读写任务之后开启SSL/TLS。
 *
 * ==== 可用的顶级秘钥:
 *
 * - INXAsyncSocketManuallyEvaluateTrust
 *     该值必须是一个NSNumber类型的BOOL值（默认为NO）
 *     如果将其设置为YES，那么底层的SecureTransport系统将不会计算对等节点的SecTrustRef。
 *     相反，它将在通常发生评估的时刻暂停，并允许我们按照我们认为合适的方式处理安全性评估。（socket:shouldTrustPeer:）
 *
 *     注意，如果您设置了这个选项，那么所有其他配置键都将被忽略。
 *     在`didReceiveTrust:completionHandler:`回调方法期间，评估将完全由您决定。
 *
 *     有关信任评估的更多信息，请参见:
 *     Apple's Technical Note TN2232 - HTTPS Server Trust Evaluation
 *     https://developer.apple.com/library/ios/technotes/tn2232/_index.html
 *
 * - INXAsyncSocketUseCFStreamForTLS (iOS only)
 *     该值必须是一个NSNumber类型的BOOL值（默认为NO）
 *     默认情况下，INXAsyncSocket将使用SecureTransport层来执行加密。
 *     这让我们对安全协议有了更多的控制(更多的配置选项)，
 *     另外，它允许我们优化系统调用和缓冲区分配。
 *
 *     但是，如果需要INXAsyncSocket也可以使用老式的加密技术（CFRead/CFWriteStream）取代SecureTransport。
 *     通过CFReadStreamSetProperty / CFWriteStreamSetProperty设置kCFStreamPropertySSLSettings并传入此方法
 *
 *     因此，INXAsyncSocket将忽略给定字典中的所有其他键，
 *     并直接传递CFReadStreamSetProperty / CFWriteStreamSetProperty。
 *     有关这些键的更多信息，请参阅kCFStreamPropertySSLSettings文档。
 *
 * ==== 可用的配置键:
 *
 * - kCFStreamSSLPeerName
 *     该值为一个NSString类型的值
 *     它应该与server提供的X.509证书中的名称匹配。
 *     详见 Apple's documentation for SSLSetPeerDomainName.
 *
 * - kCFStreamSSLCertificates
 *     该值为一个NSArray类型的值
 *     详见 Apple's documentation for SSLSetCertificate.
 *
 * - kCFStreamSSLIsServer
 *     该值必须是一个NSNumber类型的BOOL值（默认为NO）
 *     详见 Apple's documentation for SSLCreateContext for iOS.
 *
 * - INXAsyncSocketSSLPeerID
 *     该值为一个NSData类型的值
 *     如果要使用TLS会话恢复，必须设置此值。
 *     详见 Apple's documentation for SSLSetPeerID.
 *
 * - INXAsyncSocketSSLProtocolVersionMin
 * - INXAsyncSocketSSLProtocolVersionMax
 *     该值必须是一个NSNumber类型的值，参考枚举`SSLProtocol`
 *     详见 Apple's documentation for SSLSetProtocolVersionMin & SSLSetProtocolVersionMax.
 *
 * - INXAsyncSocketSSLSessionOptionFalseStart
 *     该值必须是一个NSNumber类型的BOOL值
 *     详见 Apple's documentation for kSSLSessionOptionFalseStart.
 *
 * - INXAsyncSocketSSLSessionOptionSendOneByteRecord
 *     该值必须是一个NSNumber类型的BOOL值
 *     详见 Apple's documentation for kSSLSessionOptionSendOneByteRecord.
 *
 * - INXAsyncSocketSSLCipherSuites
 *     该值为一个NSArray类型的值
 *     每个元素必须是NSNumber类型的`SSLCiphersuiteGroup`枚举值
 *     详见 Apple's documentation for SSLSetEnabledCiphers.
 *
 * - INXAsyncSocketSSLDiffieHellmanParameters (Mac OS X only)
 *     该值必须为一个NSData类型的值
 *     详见 Apple's documentation for SSLSetDiffieHellmanParams.
 *
 * ==== 失效的配制键: (会抛出异常)
 *
 * - kCFStreamSSLAllowsAnyRoot (UNAVAILABLE)
 *     您必须使用手动信任评估(参见INXAsyncSocketManuallyEvaluateTrust)。
 *     对应的弃用方法:SSLSetAllowsAnyRoot
 *
 * - kCFStreamSSLAllowsExpiredRoots (UNAVAILABLE)
 *     您必须使用手动信任评估(参见INXAsyncSocketManuallyEvaluateTrust)。
 *     对应的弃用方法:SSLSetAllowsExpiredRoots
 *
 * - kCFStreamSSLAllowsExpiredCertificates (UNAVAILABLE)
 *     您必须使用手动信任评估(参见INXAsyncSocketManuallyEvaluateTrust)。
 *     对应的弃用方法:SSLSetAllowsExpiredCerts
 *
 * - kCFStreamSSLValidatesCertificateChain (UNAVAILABLE)
 *     您必须使用手动信任评估(参见INXAsyncSocketManuallyEvaluateTrust)。
 *     对应的弃用方法:SSLSetEnableCertVerify
 *
 * - kCFStreamSSLLevel (UNAVAILABLE)
 *     您必须使用INXAsyncSocketSSLProtocolVersionMin & INXAsyncSocketSSLProtocolVersionMin以代替.
 *     对应的弃用方法:SSLSetProtocolVersionEnabled
 *
 *
 * 请参考苹果官方文档对应的SSLFunctions.
 *
 * 如果传空将会使用默认设置.
 *
 * 重要安全事项:
 * 默认设置将检查server证书是否由受信任的第三方证书代理机构（如：verisign）签署的，并且证书没有过期
 * 但是，它不会验证证书上的名称，除非您通过kCFStreamSSLPeerName密钥给它一个要验证的名称。
 * 理解这一点的安全含义非常重要。
 * 假设您试图创建到MySecureServer.com的安全连接，但是由于DNS服务器被黑客攻击，您的socket被指向MaliciousServer.com。
 * 如果您只是使用默认设置，并且MaliciousServer.com有一个有效的证书，那么默认设置将不会检测到任何问题，因为证书是有效的。
 * 要在此特定场景中正确保护连接，您应该将kCFStreamSSLPeerName属性设置为“MySecureServer.com”。
 *
 * 您还可以在socketDidSecure中执行额外的验证。
 **/
- (void)startTLS:(nullable NSDictionary <NSString*,NSObject*>*)tlsSettings;

#pragma mark Advanced

/**
 * 传统上，直到对话结束，socket才会关闭。
 * 当时远端接入点是可以在技术上关闭它的写流的，然后本地的socket会被通知没有更多的数据要读取。
 * 但是本地的socket仍然可以写数据，远端也可以继续读取我们的数据。
 *
 * 这是因为存在一种需求：客户端在想远端发送请求后告知远端没有进一步的请求，而远端会以此关闭写流不再向此客户端发送数据。
 * 然而实践中这种需求很少被使用到。更糟的是更糟的是，从TCP的角度看，无法区分读取流关闭和socket完全关闭。它们都导致TCP堆栈接收一个FIN包。
 * 唯一的方法是继续向socket写入。如果只是一个读流关闭，那么写操作将继续工作。
 *
 * 除了技术上的挑战和混乱，许多高级socket/流API不支持处理这个问题。如果读流被关闭，API立即声明要关闭socket，并关闭写流。
 * 事实上，这就是苹果的CFStream API所做的。乍一看，这听起来像是糟糕的设计，但实际上它简化了开发。
 *
 * 大多数情况下，如果读取流被关闭，那是因为远程端点关闭了它的socket。因此，此时关闭socket实际上是有意义的。
 * 事实上，这正是大多数网络开发人员所希望和期望的。
 * 然而，如果您正在编写一个与大量客户端交互的服务器，您可能会遇到一个客户端使用不推荐的关闭其写流的技术。
 * 如果是这种情况，可以将此属性设置为NO，并使用`socketDidCloseReadStream`代理方法。
 *
 * 默认 YES.
 **/
@property (atomic, assign, readwrite) BOOL autoDisconnectOnClosedReadStream;

/**
 * INXAsyncSocket使用内部串行dispatch_queue维护线程安全。
 * 在大多数情况下，实例本身创建这个队列。
 * 但是，为了实现最大的灵活性，可以在init方法中传递内部队列。
 * 这允许一些高级选项，比如通过目标队列控制socket优先级。
 * 然而，当开始使用像这样的目标队列时，就会出现一些特定的死锁问题（在目标队列同步执行相关方法）。
 *
 * 这个示例演示了在某些服务器中形成优先级（socketQueue -> ipQueue -> moduleQueue）。
 * - (dispatch_queue_t)newSocketQueueForConnectionFromAddress:(NSData *)address onSocket:(INXAsyncSocket *)sock
 * {
 *     dispatch_queue_t socketQueue = dispatch_queue_create("", NULL);
 *     dispatch_queue_t ipQueue = [self ipQueueForAddress:address];
 *
 *     dispatch_set_target_queue(socketQueue, ipQueue);
 *     dispatch_set_target_queue(iqQueue, moduleQueue);
 *
 *     return socketQueue;
 * }
 * - (void)socket:(INXAsyncSocket *)sock didAcceptNewSocket:(INXAsyncSocket *)newSocket
 * {
 *     [clientConnections addObject:newSocket];
 *     [newSocket markSocketQueueTargetQueue:moduleQueue];
 * }
 *
 * Note: 只有当您打算直接在ipQueue或moduleQueue上执行代码时，才需要此解决方案。
 * 通常情况并非如此，因为此类队列仅用于执行shaping。
 **/
- (void)markSocketQueueTargetQueue:(dispatch_queue_t)socketQueuesPreConfiguredTargetQueue;
- (void)unmarkSocketQueueTargetQueue:(dispatch_queue_t)socketQueuesPreviouslyConfiguredTargetQueue;

/**
 * 从socket的内部队列外访问某些变量不是线程安全的。
 *
 * 例如，socket文件描述符。
 * 文件描述符只是引用每个进程文件表中的索引的整数。
 * 但是，当请求一个新的文件描述符(通过打开文件或socket)时，返回的文件描述符保证是编号最少的未使用的描述符。
 * 所以如果我们不小心的话，下面这些是可能的:
 *
 * - 线程A调用一个方法，该方法返回socket的文件描述符。
 * - socket在线程B上的内部队列关闭。
 * - 线程C打开一个文件，然后接收先前是socketFD的文件描述符。
 * - 线程A现在正在访问/修改文件，而不是socket。
 *
 * 除此之外，其他变量实际上不是对象，因此不能保留/释放，甚至不能自动释放。
 * 一个例子是sslContext，类型为SSLContextRef，它实际上是一个malloc'd struct。
 *
 * 尽管有一些内部变量使得维护线程安全变得困难，但提供对这些变量的访问非常重要，确保该类可以在广泛的环境中使用。
 * 此方法通过调用socket内部队列上的当前块来帮助完成此任务。
 * 可以在block中调用下面的方法，以线程安全的方式访问那些通常不安全的内部变量。
 * 给定的block将在socket的内部队列上同步调用。
 *
 * 如果您保存对任何受保护变量的引用，并在块之外使用它们，那么您这样做的后果自负。
 **/
- (void)performBlock:(dispatch_block_t)block;

/**
 * 这些方法只能在`performBlock:`上下文中使用。
 *
 * 提供对socket的文件描述符的访问。
 * 如果socket是正在接受传入连接的服务器socket，它实际上可能有多个内部socket文件描述符（一个用于IPv4，一个用于IPv6）。
 **/
- (int)socketFD;
- (int)socket4FD;
- (int)socket6FD;

#if TARGET_OS_IPHONE

/**
 * 这些方法只能在`performBlock:`上下文中使用。
 *
 * 提供对socket内部CFReadStream/CFWriteStream的访问。
 *
 * 这些流仅用于解决iOS的特定缺陷:
 *
 * - 苹果公司决定将SecureTransport框架保持为iOS私有。
 *   这意味着提供的惟一SSL/TLS方法是通过CFStream或它之上的一些其他API。
 *   因此，为了在iOS上提供SSL/TLS支持，我们不得不依赖CFStream，
 *   而不是首选的更快更强大的安全传输。
 *
 * - 如果一个socket没有启用后台开关，并且在应用程序进入后台时该socket会被关闭，
 *   苹果只需要通过CFStream API通知我们。
 *   在这种情况下，更快更强大的GCD API没有得到适当的通知。
 *
 * 详见: (BOOL)enableBackgroundingOnSocket
 **/
- (nullable CFReadStreamRef)readStream;
- (nullable CFWriteStreamRef)writeStream;

/**
 * 这个方法只能在`performBlock:`上下文中使用。
 *
 * 配置socket，使其能够在iOS应用程序后台运行时操作。
 * 换句话说，这个方法创建一个读和写流，并调用:
 *
 * CFReadStreamSetProperty(readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
 * CFWriteStreamSetProperty(writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
 *
 * 如果成功，返回YES，否则返回NO。
 *
 * 注意:苹果官方不支持后台服务器socket。
 * 也就是说，如果您的socket正在接受传入连接，那么苹果官方并不支持在应用程序后台运行时允许iOS应用程序接受传入连接。
 *
 * 示例:
 *
 * - (void)socket:(INXAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port
 * {
 *     [asyncSocket performBlock:^{
 *         [asyncSocket enableBackgroundingOnSocket];
 *     }];
 * }
 **/
- (BOOL)enableBackgroundingOnSocket;

#endif

/**
 * 这个方法只能在`performBlock:`上下文中使用。
 *
 * 如果socket上已启动SSL/TLS，则提供对socket的SSLContext的访问。
 **/
- (nullable SSLContextRef)sslContext;

#pragma mark Utilities

/**
 * INXAsyncSocket使用的地址查找类方法。
 * 这个方法是同步的，所以建议您在后台线程/队列中使用它
 *
 * 特殊字符串“localhost”和“loopback”返回IPv4和IPv6的环回地址。
 *
 * @returns
 *   一个可变数组，包含`getaddrinfo`返回的所有IPv4和IPv6地址。
 *   这些地址是专门针对TCP连接的。
 *   如果需要，可以使用INXAsyncSocket类提供的其他方法过滤地址。
 **/
+ (nullable NSMutableArray *)lookupHost:(NSString *)host port:(uint16_t)port error:(NSError **)errPtr;

/**
 * 从原始地址数据中提取主机和端口信息。
 **/

+ (nullable NSString *)hostFromAddress:(NSData *)address;
+ (uint16_t)portFromAddress:(NSData *)address;

+ (BOOL)isIPv4Address:(NSData *)address;
+ (BOOL)isIPv6Address:(NSData *)address;

+ (BOOL)getHost:( NSString * __nullable * __nullable)hostPtr port:(nullable uint16_t *)portPtr fromAddress:(NSData *)address;

+ (BOOL)getHost:(NSString * __nullable * __nullable)hostPtr port:(nullable uint16_t *)portPtr family:(nullable sa_family_t *)afPtr fromAddress:(NSData *)address;

/**
 * 一些常用的行分隔符，用于readDataToData:…方法。
 **/
+ (NSData *)CRLFData;   // 0x0D0A
+ (NSData *)CRData;     // 0x0D
+ (NSData *)LFData;     // 0x0A
+ (NSData *)ZeroData;   // 0x00

@end
NS_ASSUME_NONNULL_END

