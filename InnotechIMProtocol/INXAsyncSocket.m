//
//  INXAsyncSocket.m
//  InnotechIMSDK
//
//  Created by jocer on 2019/5/22.
//  Copyright © 2019 jocer. All rights reserved.
//

#import "INXAsyncSocket.h"

#if TARGET_OS_IPHONE
#import <CFNetwork/CFNetwork.h>
#endif

#import <TargetConditionals.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <netinet/in.h>
#import <net/if.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <sys/poll.h>
#import <sys/uio.h>
#import <sys/un.h>
#import <unistd.h>

#import "INXAsyncReadPacket.h"
#import "INXAsyncSocketPreBuffer.h"
#import "INXAsyncWritePacket.h"
#import "INXAsyncSpecialPacket.h"
#import "INXAsyncSocketDelegate.h"

#if ! __has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
#endif


#ifndef INXAsyncSocketLoggingEnabled
#define INXAsyncSocketLoggingEnabled 0
#endif

#if INXAsyncSocketLoggingEnabled

// Logging Enabled - See log level below

// Logging uses the CocoaLumberjack framework (which is also GCD based).
// https://github.com/robbiehanson/CocoaLumberjack
//
// It allows us to do a lot of logging without significantly slowing down the code.
#import "DDLog.h"

#define LogAsync   YES
#define LogContext INXAsyncSocketLoggingContext

#define LogObjc(flg, frmt, ...) LOG_OBJC_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)
#define LogC(flg, frmt, ...)    LOG_C_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)

#define LogError(frmt, ...)     LogObjc(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogObjc(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogObjc(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogObjc(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogCError(frmt, ...)    LogC(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCWarn(frmt, ...)     LogC(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCInfo(frmt, ...)     LogC(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCVerbose(frmt, ...)  LogC(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogTrace()              LogObjc(LOG_FLAG_VERBOSE, @"%@: %@", THIS_FILE, THIS_METHOD)
#define LogCTrace()             LogC(LOG_FLAG_VERBOSE, @"%@: %s", THIS_FILE, __FUNCTION__)

#ifndef INXAsyncSocketLogLevel
#define INXAsyncSocketLogLevel LOG_LEVEL_VERBOSE
#endif

// Log levels : off, error, warn, info, verbose
static const int logLevel = INXAsyncSocketLogLevel;

#else

// Logging Disabled

#define LogError(frmt, ...)     {}
#define LogWarn(frmt, ...)      {}
#define LogInfo(frmt, ...)      {}
#define LogVerbose(frmt, ...)   {}

#define LogCError(frmt, ...)    {}
#define LogCWarn(frmt, ...)     {}
#define LogCInfo(frmt, ...)     {}
#define LogCVerbose(frmt, ...)  {}

#define LogTrace()              {}
#define LogCTrace(frmt, ...)    {}

#endif

/**
 * Seeing a return statements within an inner block
 * can sometimes be mistaken for a return point of the enclosing method.
 * This makes inline blocks a bit easier to read.
 **/
#define return_from_block  return

/**
 * A socket file descriptor is really just an integer.
 * It represents the index of the socket within the kernel.
 * This makes invalid file descriptor comparisons easier to read.
 **/
#define SOCKET_NULL -1


NSString *const INXAsyncSocketException = @"INXAsyncSocketException";
NSString *const INXAsyncSocketErrorDomain = @"INXAsyncSocketErrorDomain";

NSString *const INXAsyncSocketQueueName = @"INXAsyncSocket";
NSString *const INXAsyncSocketThreadName = @"INXAsyncSocket-CFStream";

NSString *const INXAsyncSocketManuallyEvaluateTrust = @"INXAsyncSocketManuallyEvaluateTrust";
#if TARGET_OS_IPHONE
NSString *const INXAsyncSocketUseCFStreamForTLS = @"INXAsyncSocketUseCFStreamForTLS";
#endif
NSString *const INXAsyncSocketSSLPeerID = @"INXAsyncSocketSSLPeerID";
NSString *const INXAsyncSocketSSLProtocolVersionMin = @"INXAsyncSocketSSLProtocolVersionMin";
NSString *const INXAsyncSocketSSLProtocolVersionMax = @"INXAsyncSocketSSLProtocolVersionMax";
NSString *const INXAsyncSocketSSLSessionOptionFalseStart = @"INXAsyncSocketSSLSessionOptionFalseStart";
NSString *const INXAsyncSocketSSLSessionOptionSendOneByteRecord = @"INXAsyncSocketSSLSessionOptionSendOneByteRecord";
NSString *const INXAsyncSocketSSLCipherSuites = @"INXAsyncSocketSSLCipherSuites";
#if !TARGET_OS_IPHONE
NSString *const INXAsyncSocketSSLDiffieHellmanParameters = @"INXAsyncSocketSSLDiffieHellmanParameters";
#endif

enum INXAsyncSocketFlags
{
    kSocketStarted                 = 1 <<  0,  // If set, socket has been started (accepting/connecting)
    kConnected                     = 1 <<  1,  // If set, the socket is connected
    kForbidReadsWrites             = 1 <<  2,  // If set, no new reads or writes are allowed
    kReadsPaused                   = 1 <<  3,  // If set, reads are paused due to possible timeout
    kWritesPaused                  = 1 <<  4,  // If set, writes are paused due to possible timeout
    kDisconnectAfterReads          = 1 <<  5,  // If set, disconnect after no more reads are queued
    kDisconnectAfterWrites         = 1 <<  6,  // If set, disconnect after no more writes are queued
    kSocketCanAcceptBytes          = 1 <<  7,  // If set, we know socket can accept bytes. If unset, it's unknown.
    kReadSourceSuspended           = 1 <<  8,  // If set, the read source is suspended
    kWriteSourceSuspended          = 1 <<  9,  // If set, the write source is suspended
    kQueuedTLS                     = 1 << 10,  // If set, we've queued an upgrade to TLS
    kStartingReadTLS               = 1 << 11,  // If set, we're waiting for TLS negotiation to complete
    kStartingWriteTLS              = 1 << 12,  // If set, we're waiting for TLS negotiation to complete
    kSocketSecure                  = 1 << 13,  // If set, socket is using secure communication via SSL/TLS
    kSocketHasReadEOF              = 1 << 14,  // If set, we have read EOF from socket
    kReadStreamClosed              = 1 << 15,  // If set, we've read EOF plus prebuffer has been drained
    kDealloc                       = 1 << 16,  // If set, the socket is being deallocated
#if TARGET_OS_IPHONE
    kAddedStreamsToRunLoop         = 1 << 17,  // If set, CFStreams have been added to listener thread
    kUsingCFStreamForTLS           = 1 << 18,  // If set, we're forced to use CFStream instead of SecureTransport
    kSecureSocketHasBytesAvailable = 1 << 19,  // If set, CFReadStream has notified us of bytes available
#endif
};

enum INXAsyncSocketConfig
{
    kIPv4Disabled              = 1 << 0,  // If set, IPv4 is disabled
    kIPv6Disabled              = 1 << 1,  // If set, IPv6 is disabled
    kPreferIPv6                = 1 << 2,  // If set, IPv6 is preferred over IPv4
    kAllowHalfDuplexConnection = 1 << 3,  // If set, the socket will stay open even if the read stream closes
};

#if TARGET_OS_IPHONE
static NSThread *cfstreamThread;  // Used for CFStreams


static uint64_t cfstreamThreadRetainCount;   // setup & teardown
static dispatch_queue_t cfstreamThreadSetupQueue; // setup & teardown
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@implementation INXAsyncSocket
{
    //flags，当前正在做操作的标识符
    uint32_t flags;
    uint16_t config;
    
    //代理
    __weak id<INXAsyncSocketDelegate> delegate;
    //代理回调的queue
    dispatch_queue_t delegateQueue;
    
    //本地IPV4Socket
    int socket4FD;
    //本地IPV6Socket
    int socket6FD;
    //unix域的socket
    int socketUN;
    //unix域 服务端 url
    NSURL *socketUrl;
    //状态Index
    int stateIndex;
    
    //本机的IPV4地址
    NSData * connectInterface4;
    //本机的IPV6地址
    NSData * connectInterface6;
    //本机unix域地址
    NSData * connectInterfaceUN;
    
    //这个类的对Socket的操作都在这个queue中，串行
    dispatch_queue_t socketQueue;
    
    dispatch_source_t accept4Source;
    dispatch_source_t accept6Source;
    dispatch_source_t acceptUNSource;
    //连接timer,GCD定时器
    dispatch_source_t connectTimer;
    dispatch_source_t readSource;
    dispatch_source_t writeSource;
    dispatch_source_t readTimer;
    dispatch_source_t writeTimer;
    
    //读写数据包数组 类似queue，最大限制为5个包
    NSMutableArray *readQueue;
    NSMutableArray *writeQueue;
    
    //当前正在读写数据包
    INXAsyncReadPacket *currentRead;
    INXAsyncWritePacket *currentWrite;
    
    //当前socket未获取完的数据大小
    unsigned long socketFDBytesAvailable;
    
    //全局公用的提前缓冲区
    INXAsyncSocketPreBuffer *preBuffer;
    
#if TARGET_OS_IPHONE
    CFStreamClientContext streamContext;
    //读写数据流
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
#endif
    //SSL上下文，用来做SSL认证
    SSLContextRef sslContext;
    //全局公用的SSL的提前缓冲区
    INXAsyncSocketPreBuffer *sslPreBuffer;
    size_t sslWriteCachedLength;
    //记录SSL读取数据错误
    OSStatus sslErrCode;
    //记录SSL握手的错误
    OSStatus lastSSLHandshakeError;
    
    //socket队列的标识key
    void *IsOnSocketQueueOrTargetQueueKey;
    
    id userData;
    //连接备选服务端地址的延时 （另一个IPV4或IPV6）
    NSTimeInterval alternateAddressDelay;
}

- (id)init
{
    return [self initWithDelegate:nil delegateQueue:NULL socketQueue:NULL];
}

- (id)initWithSocketQueue:(dispatch_queue_t)sq
{
    return [self initWithDelegate:nil delegateQueue:NULL socketQueue:sq];
}

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq
{
    return [self initWithDelegate:aDelegate delegateQueue:dq socketQueue:NULL];
}

- (id)initWithDelegate:(id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq
{
    if((self = [super init]))
    {
        delegate = aDelegate;
        delegateQueue = dq;
        
#if !OS_OBJECT_USE_OBJC
        if (dq) dispatch_retain(dq);
#endif
        
        //init
        socket4FD = SOCKET_NULL;
        socket6FD = SOCKET_NULL;
        socketUN = SOCKET_NULL;
        socketUrl = nil;
        stateIndex = 0;
        
        if (sq)
        {
            NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
                     @"The given socketQueue parameter must not be a concurrent queue.");
            NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0),
                     @"The given socketQueue parameter must not be a concurrent queue.");
            NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                     @"The given socketQueue parameter must not be a concurrent queue.");
            
            socketQueue = sq;
#if !OS_OBJECT_USE_OBJC
            dispatch_retain(sq);
#endif
        }
        else
        {
            socketQueue = dispatch_queue_create([INXAsyncSocketQueueName UTF8String], NULL);
        }
        
        // The dispatch_queue_set_specific() and dispatch_get_specific() functions take a "void *key" parameter.
        // From the documentation:
        //
        // > Keys are only compared as pointers and are never dereferenced.
        // > Thus, you can use a pointer to a static variable for a specific subsystem or
        // > any other value that allows you to identify the value uniquely.
        //
        // We're just going to use the memory address of an ivar.
        // Specifically an ivar that is explicitly named for our purpose to make the code more readable.
        //
        // However, it feels tedious (and less readable) to include the "&" all the time:
        // dispatch_get_specific(&IsOnSocketQueueOrTargetQueueKey)
        //
        // So we're going to make it so it doesn't matter if we use the '&' or not,
        // by assigning the value of the ivar to the address of the ivar.
        // Thus: IsOnSocketQueueOrTargetQueueKey == &IsOnSocketQueueOrTargetQueueKey;
        
        IsOnSocketQueueOrTargetQueueKey = &IsOnSocketQueueOrTargetQueueKey;
        
        void *nonNullUnusedPointer = (__bridge void *)self;
        dispatch_queue_set_specific(socketQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
        
        //init 读写队列最大5，缓存大小4kb，交替连接延迟0.3s
        readQueue = [[NSMutableArray alloc] initWithCapacity:5];
        currentRead = nil;
        
        writeQueue = [[NSMutableArray alloc] initWithCapacity:5];
        currentWrite = nil;
        
        preBuffer = [[INXAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
        alternateAddressDelay = 0.3;
    }
    return self;
}

- (void)dealloc
{
    LogInfo(@"%@ - %@ (start)", THIS_METHOD, self);
    
    // Set dealloc flag.
    // This is used by closeWithError to ensure we don't accidentally retain ourself.
    flags |= kDealloc;
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        [self closeWithError:nil];
    }
    else
    {
        dispatch_sync(socketQueue, ^{
            [self closeWithError:nil];
        });
    }
    
    delegate = nil;
    
#if !OS_OBJECT_USE_OBJC
    if (delegateQueue) dispatch_release(delegateQueue);
#endif
    delegateQueue = NULL;
    
#if !OS_OBJECT_USE_OBJC
    if (socketQueue) dispatch_release(socketQueue);
#endif
    socketQueue = NULL;
    
    LogInfo(@"%@ - %@ (finish)", THIS_METHOD, self);
}

#pragma mark -

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD socketQueue:(nullable dispatch_queue_t)sq error:(NSError**)error {
    return [self socketFromConnectedSocketFD:socketFD delegate:nil delegateQueue:NULL socketQueue:sq error:error];
}

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq error:(NSError**)error {
    return [self socketFromConnectedSocketFD:socketFD delegate:aDelegate delegateQueue:dq socketQueue:NULL error:error];
}

+ (nullable instancetype)socketFromConnectedSocketFD:(int)socketFD delegate:(nullable id<INXAsyncSocketDelegate>)aDelegate delegateQueue:(nullable dispatch_queue_t)dq socketQueue:(nullable dispatch_queue_t)sq error:(NSError* __autoreleasing *)error
{
    __block BOOL errorOccured = NO;
    
    INXAsyncSocket *socket = [[[self class] alloc] initWithDelegate:aDelegate delegateQueue:dq socketQueue:sq];
    
    dispatch_sync(socket->socketQueue, ^{ @autoreleasepool {
        struct sockaddr addr;
        socklen_t addr_size = sizeof(struct sockaddr);
        int retVal = getpeername(socketFD, (struct sockaddr *)&addr, &addr_size);
        if (retVal)
        {
            NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketOtherError",
                                                                 @"INXAsyncSocket", [NSBundle mainBundle],
                                                                 @"Attempt to create socket from socket FD failed. getpeername() failed", nil);
            
            NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
            
            errorOccured = YES;
            if (error)
                *error = [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketOtherError userInfo:userInfo];
            return;
        }
        
        if (addr.sa_family == AF_INET)
        {
            socket->socket4FD = socketFD;
        }
        else if (addr.sa_family == AF_INET6)
        {
            socket->socket6FD = socketFD;
        }
        else
        {
            NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketOtherError",
                                                                 @"INXAsyncSocket", [NSBundle mainBundle],
                                                                 @"Attempt to create socket from socket FD failed. socket FD is neither IPv4 nor IPv6", nil);
            
            NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
            
            errorOccured = YES;
            if (error)
                *error = [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketOtherError userInfo:userInfo];
            return;
        }
        
        socket->flags = kSocketStarted;
        [socket didConnect:socket->stateIndex];
    }});
    
    return errorOccured? nil: socket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Configuration
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (id)delegate
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return delegate;
    }
    else
    {
        __block id result;
        
        dispatch_sync(socketQueue, ^{
            result = self->delegate;
        });
        
        return result;
    }
}

- (void)setDelegate:(id)newDelegate synchronously:(BOOL)synchronously
{
    dispatch_block_t block = ^{
        self->delegate = newDelegate;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
        block();
    }
    else {
        if (synchronously)
            dispatch_sync(socketQueue, block);
        else
            dispatch_async(socketQueue, block);
    }
}

- (void)setDelegate:(id)newDelegate
{
    [self setDelegate:newDelegate synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate
{
    [self setDelegate:newDelegate synchronously:YES];
}

- (dispatch_queue_t)delegateQueue
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return delegateQueue;
    }
    else
    {
        __block dispatch_queue_t result;
        
        dispatch_sync(socketQueue, ^{
            result = self->delegateQueue;
        });
        
        return result;
    }
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
    dispatch_block_t block = ^{
        
#if !OS_OBJECT_USE_OBJC
        if (self->delegateQueue) dispatch_release(self->delegateQueue);
        if (newDelegateQueue) dispatch_retain(newDelegateQueue);
#endif
        
        self->delegateQueue = newDelegateQueue;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
        block();
    }
    else {
        if (synchronously)
            dispatch_sync(socketQueue, block);
        else
            dispatch_async(socketQueue, block);
    }
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
    [self setDelegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
    [self setDelegateQueue:newDelegateQueue synchronously:YES];
}

- (void)getDelegate:(id<INXAsyncSocketDelegate> *)delegatePtr delegateQueue:(dispatch_queue_t *)delegateQueuePtr
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (delegatePtr) *delegatePtr = delegate;
        if (delegateQueuePtr) *delegateQueuePtr = delegateQueue;
    }
    else
    {
        __block id dPtr = NULL;
        __block dispatch_queue_t dqPtr = NULL;
        
        dispatch_sync(socketQueue, ^{
            dPtr = self->delegate;
            dqPtr = self->delegateQueue;
        });
        
        if (delegatePtr) *delegatePtr = dPtr;
        if (delegateQueuePtr) *delegateQueuePtr = dqPtr;
    }
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
    dispatch_block_t block = ^{
        
        self->delegate = newDelegate;
        
#if !OS_OBJECT_USE_OBJC
        if (self->delegateQueue) dispatch_release(self->delegateQueue);
        if (newDelegateQueue) dispatch_retain(newDelegateQueue);
#endif
        
        self->delegateQueue = newDelegateQueue;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
        block();
    }
    else {
        if (synchronously)
            dispatch_sync(socketQueue, block);
        else
            dispatch_async(socketQueue, block);
    }
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
    [self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
    [self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:YES];
}

- (BOOL)isIPv4Enabled
{
    // Note: YES means kIPv4Disabled is OFF
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return ((config & kIPv4Disabled) == 0);
    }
    else
    {
        __block BOOL result;
        
        dispatch_sync(socketQueue, ^{
            result = ((self->config & kIPv4Disabled) == 0);
        });
        
        return result;
    }
}

- (void)setIPv4Enabled:(BOOL)flag
{
    // Note: YES means kIPv4Disabled is OFF
    
    dispatch_block_t block = ^{
        
        if (flag)
            self->config &= ~kIPv4Disabled;
        else
            self->config |= kIPv4Disabled;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

- (BOOL)isIPv6Enabled
{
    // Note: YES means kIPv6Disabled is OFF
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return ((config & kIPv6Disabled) == 0);
    }
    else
    {
        __block BOOL result;
        
        dispatch_sync(socketQueue, ^{
            result = ((self->config & kIPv6Disabled) == 0);
        });
        
        return result;
    }
}

- (void)setIPv6Enabled:(BOOL)flag
{
    // Note: YES means kIPv6Disabled is OFF
    
    dispatch_block_t block = ^{
        
        if (flag)
            self->config &= ~kIPv6Disabled;
        else
            self->config |= kIPv6Disabled;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

- (BOOL)isIPv4PreferredOverIPv6
{
    // Note: YES means kPreferIPv6 is OFF
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return ((config & kPreferIPv6) == 0);
    }
    else
    {
        __block BOOL result;
        
        dispatch_sync(socketQueue, ^{
            result = ((self->config & kPreferIPv6) == 0);
        });
        
        return result;
    }
}

- (void)setIPv4PreferredOverIPv6:(BOOL)flag
{
    // Note: YES means kPreferIPv6 is OFF
    
    dispatch_block_t block = ^{
        
        if (flag)
            self->config &= ~kPreferIPv6;
        else
            self->config |= kPreferIPv6;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

- (NSTimeInterval) alternateAddressDelay {
    __block NSTimeInterval delay;
    dispatch_block_t block = ^{
        delay = self->alternateAddressDelay;
    };
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    return delay;
}

- (void) setAlternateAddressDelay:(NSTimeInterval)delay {
    dispatch_block_t block = ^{
        self->alternateAddressDelay = delay;
    };
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

- (id)userData
{
    __block id result = nil;
    
    dispatch_block_t block = ^{
        
        result = self->userData;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

- (void)setUserData:(id)arbitraryUserData
{
    dispatch_block_t block = ^{
        
        if (self->userData != arbitraryUserData)
        {
            self->userData = arbitraryUserData;
        }
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Accepting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (BOOL)acceptOnPort:(uint16_t)port error:(NSError **)errPtr
{
    return [self acceptOnInterface:nil port:port error:errPtr];
}

- (BOOL)acceptOnInterface:(NSString *)inInterface port:(uint16_t)port error:(NSError **)errPtr
{
    LogTrace();
    
    // Just in-case interface parameter is immutable.
    NSString *interface = [inInterface copy];
    
    __block BOOL result = NO;
    __block NSError *err = nil;
    
    // CreateSocket Block
    // This block will be invoked within the dispatch block below.
    
    int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
        
        int socketFD = socket(domain, SOCK_STREAM, 0);
        
        if (socketFD == SOCKET_NULL)
        {
            NSString *reason = @"Error in socket() function";
            err = [self errorWithErrno:errno reason:reason];
            
            return SOCKET_NULL;
        }
        
        int status;
        
        // Set socket options
        
        status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
        if (status == -1)
        {
            NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        int reuseOn = 1;
        status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        if (status == -1)
        {
            NSString *reason = @"Error enabling address reuse (setsockopt)";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        // Bind socket
        
        status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
        if (status == -1)
        {
            NSString *reason = @"Error in bind() function";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        // Listen
        
        status = listen(socketFD, 1024);
        if (status == -1)
        {
            NSString *reason = @"Error in listen() function";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        return socketFD;
    };
    
    // Create dispatch block and run on socketQueue
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if (self->delegate == nil) // Must have delegate set
        {
            NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        if (self->delegateQueue == NULL) // Must have delegate queue set
        {
            NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        BOOL isIPv4Disabled = (self->config & kIPv4Disabled) ? YES : NO;
        BOOL isIPv6Disabled = (self->config & kIPv6Disabled) ? YES : NO;
        
        if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
        {
            NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        if (![self isDisconnected]) // Must be disconnected
        {
            NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        // Clear queues (spurious read/write requests post disconnect)
        [self->readQueue removeAllObjects];
        [self->writeQueue removeAllObjects];
        
        // Resolve interface from description
        
        NSMutableData *interface4 = nil;
        NSMutableData *interface6 = nil;
        
        [self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:port];
        
        if ((interface4 == nil) && (interface6 == nil))
        {
            NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        if (isIPv4Disabled && (interface6 == nil))
        {
            NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        if (isIPv6Disabled && (interface4 == nil))
        {
            NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        BOOL enableIPv4 = !isIPv4Disabled && (interface4 != nil);
        BOOL enableIPv6 = !isIPv6Disabled && (interface6 != nil);
        
        // Create sockets, configure, bind, and listen
        
        if (enableIPv4)
        {
            LogVerbose(@"Creating IPv4 socket");
            self->socket4FD = createSocket(AF_INET, interface4);
            
            if (self->socket4FD == SOCKET_NULL)
            {
                return_from_block;
            }
        }
        
        if (enableIPv6)
        {
            LogVerbose(@"Creating IPv6 socket");
            
            if (enableIPv4 && (port == 0))
            {
                // No specific port was specified, so we allowed the OS to pick an available port for us.
                // Now we need to make sure the IPv6 socket listens on the same port as the IPv4 socket.
                
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)[interface6 mutableBytes];
                addr6->sin6_port = htons([self localPort4]);
            }
            
            self->socket6FD = createSocket(AF_INET6, interface6);
            
            if (self->socket6FD == SOCKET_NULL)
            {
                if (self->socket4FD != SOCKET_NULL)
                {
                    LogVerbose(@"close(socket4FD)");
                    close(self->socket4FD);
                }
                
                return_from_block;
            }
        }
        
        // Create accept sources
        
        if (enableIPv4)
        {
            self->accept4Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, self->socket4FD, 0, self->socketQueue);
            
            int socketFD = self->socket4FD;
            dispatch_source_t acceptSource = self->accept4Source;
            
            __weak INXAsyncSocket *weakSelf = self;
            
            dispatch_source_set_event_handler(self->accept4Source, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
                
                __strong INXAsyncSocket *strongSelf = weakSelf;
                if (strongSelf == nil) return_from_block;
                
                LogVerbose(@"event4Block");
                
                unsigned long i = 0;
                unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
                
                LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
                
                while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
                
#pragma clang diagnostic pop
            }});
            
            
            dispatch_source_set_cancel_handler(self->accept4Source, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
                
#if !OS_OBJECT_USE_OBJC
                LogVerbose(@"dispatch_release(accept4Source)");
                dispatch_release(acceptSource);
#endif
                
                LogVerbose(@"close(socket4FD)");
                close(socketFD);
                
#pragma clang diagnostic pop
            });
            
            LogVerbose(@"dispatch_resume(accept4Source)");
            dispatch_resume(self->accept4Source);
        }
        
        if (enableIPv6)
        {
            self->accept6Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, self->socket6FD, 0, self->socketQueue);
            
            int socketFD = self->socket6FD;
            dispatch_source_t acceptSource = self->accept6Source;
            
            __weak INXAsyncSocket *weakSelf = self;
            
            dispatch_source_set_event_handler(self->accept6Source, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
                
                __strong INXAsyncSocket *strongSelf = weakSelf;
                if (strongSelf == nil) return_from_block;
                
                LogVerbose(@"event6Block");
                
                unsigned long i = 0;
                unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
                
                LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
                
                while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
                
#pragma clang diagnostic pop
            }});
            
            dispatch_source_set_cancel_handler(self->accept6Source, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
                
#if !OS_OBJECT_USE_OBJC
                LogVerbose(@"dispatch_release(accept6Source)");
                dispatch_release(acceptSource);
#endif
                
                LogVerbose(@"close(socket6FD)");
                close(socketFD);
                
#pragma clang diagnostic pop
            });
            
            LogVerbose(@"dispatch_resume(accept6Source)");
            dispatch_resume(self->accept6Source);
        }
        
        self->flags |= kSocketStarted;
        
        result = YES;
    }};
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    if (result == NO)
    {
        LogInfo(@"Error in accept: %@", err);
        
        if (errPtr)
            *errPtr = err;
    }
    
    return result;
}

- (BOOL)acceptOnUrl:(NSURL *)url error:(NSError **)errPtr;
{
    LogTrace();
    
    __block BOOL result = NO;
    __block NSError *err = nil;
    
    // CreateSocket Block
    // This block will be invoked within the dispatch block below.
    
    int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
        
        int socketFD = socket(domain, SOCK_STREAM, 0);
        
        if (socketFD == SOCKET_NULL)
        {
            NSString *reason = @"Error in socket() function";
            err = [self errorWithErrno:errno reason:reason];
            
            return SOCKET_NULL;
        }
        
        int status;
        
        // Set socket options
        
        status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
        if (status == -1)
        {
            NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        int reuseOn = 1;
        status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        if (status == -1)
        {
            NSString *reason = @"Error enabling address reuse (setsockopt)";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        // Bind socket
        
        status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
        if (status == -1)
        {
            NSString *reason = @"Error in bind() function";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        // Listen
        
        status = listen(socketFD, 1024);
        if (status == -1)
        {
            NSString *reason = @"Error in listen() function";
            err = [self errorWithErrno:errno reason:reason];
            
            LogVerbose(@"close(socketFD)");
            close(socketFD);
            return SOCKET_NULL;
        }
        
        return socketFD;
    };
    
    // Create dispatch block and run on socketQueue
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if (self->delegate == nil) // Must have delegate set
        {
            NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        if (self->delegateQueue == NULL) // Must have delegate queue set
        {
            NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        if (![self isDisconnected]) // Must be disconnected
        {
            NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
            err = [self badConfigError:msg];
            
            return_from_block;
        }
        
        // Clear queues (spurious read/write requests post disconnect)
        [self->readQueue removeAllObjects];
        [self->writeQueue removeAllObjects];
        
        // Remove a previous socket
        
        NSError *error = nil;
        NSFileManager *fileManager = [NSFileManager defaultManager];
        if ([fileManager fileExistsAtPath:url.path]) {
            if (![[NSFileManager defaultManager] removeItemAtURL:url error:&error]) {
                NSString *msg = @"Could not remove previous unix domain socket at given url.";
                err = [self otherError:msg];
                
                return_from_block;
            }
        }
        
        // Resolve interface from description
        
        NSData *interface = [self getInterfaceAddressFromUrl:url];
        
        if (interface == nil)
        {
            NSString *msg = @"Invalid unix domain url. Specify a valid file url that does not exist (e.g. \"file:///tmp/socket\")";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        // Create sockets, configure, bind, and listen
        
        LogVerbose(@"Creating unix domain socket");
        self->socketUN = createSocket(AF_UNIX, interface);
        
        if (self->socketUN == SOCKET_NULL)
        {
            return_from_block;
        }
        
        self->socketUrl = url;
        
        // Create accept sources
        
        self->acceptUNSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, self->socketUN, 0, self->socketQueue);
        
        int socketFD = self->socketUN;
        dispatch_source_t acceptSource = self->acceptUNSource;
        
        dispatch_source_set_event_handler(self->acceptUNSource, ^{ @autoreleasepool {
            
            LogVerbose(@"eventUNBlock");
            
            unsigned long i = 0;
            unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
            
            LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
            
            while ([self doAccept:socketFD] && (++i < numPendingConnections));
        }});
        
        dispatch_source_set_cancel_handler(self->acceptUNSource, ^{
            
#if NEEDS_DISPATCH_RETAIN_RELEASE
            LogVerbose(@"dispatch_release(accept4Source)");
            dispatch_release(acceptSource);
#endif
            
            LogVerbose(@"close(socket4FD)");
            close(socketFD);
        });
        
        LogVerbose(@"dispatch_resume(accept4Source)");
        dispatch_resume(self->acceptUNSource);
        
        self->flags |= kSocketStarted;
        
        result = YES;
    }};
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    if (result == NO)
    {
        LogInfo(@"Error in accept: %@", err);
        
        if (errPtr)
            *errPtr = err;
    }
    
    return result;
}

- (BOOL)doAccept:(int)parentSocketFD
{
    LogTrace();
    
    int socketType;
    int childSocketFD;
    NSData *childSocketAddress;
    
    if (parentSocketFD == socket4FD)
    {
        socketType = 0;
        
        struct sockaddr_in addr;
        socklen_t addrLen = sizeof(addr);
        
        childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
        
        if (childSocketFD == -1)
        {
            LogWarn(@"Accept failed with error: %@", [self errnoError]);
            return NO;
        }
        
        childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
    }
    else if (parentSocketFD == socket6FD)
    {
        socketType = 1;
        
        struct sockaddr_in6 addr;
        socklen_t addrLen = sizeof(addr);
        
        childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
        
        if (childSocketFD == -1)
        {
            LogWarn(@"Accept failed with error: %@", [self errnoError]);
            return NO;
        }
        
        childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
    }
    else // if (parentSocketFD == socketUN)
    {
        socketType = 2;
        
        struct sockaddr_un addr;
        socklen_t addrLen = sizeof(addr);
        
        childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
        
        if (childSocketFD == -1)
        {
            LogWarn(@"Accept failed with error: %@", [self errnoError]);
            return NO;
        }
        
        childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
    }
    
    // Enable non-blocking IO on the socket
    
    int result = fcntl(childSocketFD, F_SETFL, O_NONBLOCK);
    if (result == -1)
    {
        LogWarn(@"Error enabling non-blocking IO on accepted socket (fcntl)");
        LogVerbose(@"close(childSocketFD)");
        close(childSocketFD);
        return NO;
    }
    
    // Prevent SIGPIPE signals
    
    int nosigpipe = 1;
    setsockopt(childSocketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    
    // Notify delegate
    
    if (delegateQueue)
    {
        __strong id theDelegate = delegate;
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            // Query delegate for custom socket queue
            
            dispatch_queue_t childSocketQueue = NULL;
            
            if ([theDelegate respondsToSelector:@selector(newSocketQueueForConnectionFromAddress:onSocket:)])
            {
                childSocketQueue = [theDelegate newSocketQueueForConnectionFromAddress:childSocketAddress
                                                                              onSocket:self];
            }
            
            // Create INXAsyncSocket instance for accepted socket
            
            INXAsyncSocket *acceptedSocket = [[[self class] alloc] initWithDelegate:theDelegate
                                                                      delegateQueue:self->delegateQueue
                                                                        socketQueue:childSocketQueue];
            
            if (socketType == 0)
                acceptedSocket->socket4FD = childSocketFD;
            else if (socketType == 1)
                acceptedSocket->socket6FD = childSocketFD;
            else
                acceptedSocket->socketUN = childSocketFD;
            
            acceptedSocket->flags = (kSocketStarted | kConnected);
            
            // Setup read and write sources for accepted socket
            
            dispatch_async(acceptedSocket->socketQueue, ^{ @autoreleasepool {
                
                [acceptedSocket setupReadAndWriteSourcesForNewlyConnectedSocket:childSocketFD];
            }});
            
            // Notify delegate
            
            if ([theDelegate respondsToSelector:@selector(socket:didAcceptNewSocket:)])
            {
                [theDelegate socket:self didAcceptNewSocket:acceptedSocket];
            }
            
            // Release the socket queue returned from the delegate (it was retained by acceptedSocket)
#if !OS_OBJECT_USE_OBJC
            if (childSocketQueue) dispatch_release(childSocketQueue);
#endif
            
            // The accepted socket should have been retained by the delegate.
            // Otherwise it gets properly released when exiting the block.
        }});
    }
    
    return YES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Connecting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * This method runs through the various checks required prior to a connection attempt.
 * It is shared between the connectToHost and connectToAddress methods.
 *
 **/
- (BOOL)preConnectWithInterface:(NSString *)interface error:(NSError **)errPtr
{
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    if (delegate == nil) // Must have delegate set
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    if (delegateQueue == NULL) // Must have delegate queue set
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    if (![self isDisconnected]) // Must be disconnected
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
    BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
    
    if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
    {
        if (errPtr)
        {
            NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    if (interface)
    {
        NSMutableData *interface4 = nil;
        NSMutableData *interface6 = nil;
        
        [self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:0];
        
        if ((interface4 == nil) && (interface6 == nil))
        {
            if (errPtr)
            {
                NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
                *errPtr = [self badParamError:msg];
            }
            return NO;
        }
        
        if (isIPv4Disabled && (interface6 == nil))
        {
            if (errPtr)
            {
                NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
                *errPtr = [self badParamError:msg];
            }
            return NO;
        }
        
        if (isIPv6Disabled && (interface4 == nil))
        {
            if (errPtr)
            {
                NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
                *errPtr = [self badParamError:msg];
            }
            return NO;
        }
        
        connectInterface4 = interface4;
        connectInterface6 = interface6;
    }
    
    // Clear queues (spurious read/write requests post disconnect)
    [readQueue removeAllObjects];
    [writeQueue removeAllObjects];
    
    return YES;
}

- (BOOL)preConnectWithUrl:(NSURL *)url error:(NSError **)errPtr
{
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    if (delegate == nil) // Must have delegate set
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    if (delegateQueue == NULL) // Must have delegate queue set
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    if (![self isDisconnected]) // Must be disconnected
    {
        if (errPtr)
        {
            NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
            *errPtr = [self badConfigError:msg];
        }
        return NO;
    }
    
    NSData *interface = [self getInterfaceAddressFromUrl:url];
    
    if (interface == nil)
    {
        if (errPtr)
        {
            NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
            *errPtr = [self badParamError:msg];
        }
        return NO;
    }
    
    connectInterfaceUN = interface;
    
    // Clear queues (spurious read/write requests post disconnect)
    [readQueue removeAllObjects];
    [writeQueue removeAllObjects];
    
    return YES;
}

- (BOOL)connectToHost:(NSString*)host onPort:(uint16_t)port error:(NSError **)errPtr
{
    return [self connectToHost:host onPort:port withTimeout:-1 error:errPtr];
}

- (BOOL)connectToHost:(NSString *)host
               onPort:(uint16_t)port
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    return [self connectToHost:host onPort:port viaInterface:nil withTimeout:timeout error:errPtr];
}

- (BOOL)connectToHost:(NSString *)inHost
               onPort:(uint16_t)port
         viaInterface:(NSString *)inInterface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    LogTrace();
    
    // 以防不可变对象被传递
    NSString *host = [inHost copy];
    NSString *interface = [inInterface copy];
    
    __block BOOL result = NO;
    __block NSError *preConnectErr = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        // 检查主机参数是否有问题
        
        if ([host length] == 0)
        {
            NSString *msg = @"Invalid host parameter (nil or \"\"). Should be a domain name or IP address string.";
            preConnectErr = [self badParamError:msg];
            
            return_from_block;
        }
        
        // 通过标准的预连接检查
        
        if (![self preConnectWithInterface:interface error:&preConnectErr])
        {
            return_from_block;
        }
        
        // 我们已经通过了所有的检查。
        // 现在是开始连接过程的时候了。
        
        self->flags |= kSocketStarted;
        
        LogVerbose(@"Dispatching DNS lookup...");
        
        // 可能给定的主机参数实际上是一个NSMutableString。
        // 我们现在要复制它，在这个块中，它会被同步执行。
        // 这样，下面的异步查找块就不必担心它会发生变化。
        
        NSString *hostCpy = [host copy];
        int aStateIndex = self->stateIndex;
        __weak INXAsyncSocket *weakSelf = self;
        
        dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        dispatch_async(globalConcurrentQueue, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            NSError *lookupErr = nil;
            NSMutableArray *addresses = [[self class] lookupHost:hostCpy port:port error:&lookupErr];
            
            __strong INXAsyncSocket *strongSelf = weakSelf;
            if (strongSelf == nil) return_from_block;
            
            if (lookupErr)
            {
                dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
                    
                    [strongSelf lookup:aStateIndex didFail:lookupErr];
                }});
            }
            else
            {
                NSData *address4 = nil;
                NSData *address6 = nil;
                
                for (NSData *address in addresses)
                {
                    if (!address4 && [[self class] isIPv4Address:address])
                    {
                        address4 = address;
                    }
                    else if (!address6 && [[self class] isIPv6Address:address])
                    {
                        address6 = address;
                    }
                }
                
                dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
                    
                    [strongSelf lookup:aStateIndex didSucceedWithAddress4:address4 address6:address6];
                }});
            }
            
#pragma clang diagnostic pop
        }});
        
        [self startConnectTimeout:timeout];
        
        result = YES;
    }};
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    
    if (errPtr) *errPtr = preConnectErr;
    return result;
}

- (BOOL)connectToAddress:(NSData *)remoteAddr error:(NSError **)errPtr
{
    return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:-1 error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)remoteAddr withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr
{
    return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:timeout error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)inRemoteAddr
            viaInterface:(NSString *)inInterface
             withTimeout:(NSTimeInterval)timeout
                   error:(NSError **)errPtr
{
    LogTrace();
    
    // Just in case immutable objects were passed
    NSData *remoteAddr = [inRemoteAddr copy];
    NSString *interface = [inInterface copy];
    
    __block BOOL result = NO;
    __block NSError *err = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        // Check for problems with remoteAddr parameter
        
        NSData *address4 = nil;
        NSData *address6 = nil;
        
        if ([remoteAddr length] >= sizeof(struct sockaddr))
        {
            const struct sockaddr *sockaddr = (const struct sockaddr *)[remoteAddr bytes];
            
            if (sockaddr->sa_family == AF_INET)
            {
                if ([remoteAddr length] == sizeof(struct sockaddr_in))
                {
                    address4 = remoteAddr;
                }
            }
            else if (sockaddr->sa_family == AF_INET6)
            {
                if ([remoteAddr length] == sizeof(struct sockaddr_in6))
                {
                    address6 = remoteAddr;
                }
            }
        }
        
        if ((address4 == nil) && (address6 == nil))
        {
            NSString *msg = @"A valid IPv4 or IPv6 address was not given";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        BOOL isIPv4Disabled = (self->config & kIPv4Disabled) ? YES : NO;
        BOOL isIPv6Disabled = (self->config & kIPv6Disabled) ? YES : NO;
        
        if (isIPv4Disabled && (address4 != nil))
        {
            NSString *msg = @"IPv4 has been disabled and an IPv4 address was passed.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        if (isIPv6Disabled && (address6 != nil))
        {
            NSString *msg = @"IPv6 has been disabled and an IPv6 address was passed.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        // Run through standard pre-connect checks
        
        if (![self preConnectWithInterface:interface error:&err])
        {
            return_from_block;
        }
        
        // We've made it past all the checks.
        // It's time to start the connection process.
        
        if (![self connectWithAddress4:address4 address6:address6 error:&err])
        {
            return_from_block;
        }
        
        self->flags |= kSocketStarted;
        
        [self startConnectTimeout:timeout];
        
        result = YES;
    }};
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    if (result == NO)
    {
        if (errPtr)
            *errPtr = err;
    }
    
    return result;
}

- (BOOL)connectToUrl:(NSURL *)url withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr;
{
    LogTrace();
    
    __block BOOL result = NO;
    __block NSError *err = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        // Check for problems with host parameter
        
        if ([url.path length] == 0)
        {
            NSString *msg = @"Invalid unix domain socket url.";
            err = [self badParamError:msg];
            
            return_from_block;
        }
        
        // Run through standard pre-connect checks
        
        if (![self preConnectWithUrl:url error:&err])
        {
            return_from_block;
        }
        
        // We've made it past all the checks.
        // It's time to start the connection process.
        
        self->flags |= kSocketStarted;
        
        // Start the normal connection process
        
        NSError *connectError = nil;
        if (![self connectWithAddressUN:self->connectInterfaceUN error:&connectError])
        {
            [self closeWithError:connectError];
            
            return_from_block;
        }
        
        [self startConnectTimeout:timeout];
        
        result = YES;
    }};
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    if (result == NO)
    {
        if (errPtr)
            *errPtr = err;
    }
    
    return result;
}

- (void)lookup:(int)aStateIndex didSucceedWithAddress4:(NSData *)address4 address6:(NSData *)address6
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    NSAssert(address4 || address6, @"Expected at least one valid address");
    
    if (aStateIndex != stateIndex)
    {
        LogInfo(@"Ignoring lookupDidSucceed, already disconnected");
        
        // 连接操作已被取消。也就是说，套接字断开了，或者连接已经超时。
        return;
    }
    
    // Check for problems
    
    BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
    BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
    
    if (isIPv4Disabled && (address6 == nil))
    {
        NSString *msg = @"IPv4 has been disabled and DNS lookup found no IPv6 address.";
        
        [self closeWithError:[self otherError:msg]];
        return;
    }
    
    if (isIPv6Disabled && (address4 == nil))
    {
        NSString *msg = @"IPv6 has been disabled and DNS lookup found no IPv4 address.";
        
        [self closeWithError:[self otherError:msg]];
        return;
    }
    
    // Start the normal connection process
    
    NSError *err = nil;
    if (![self connectWithAddress4:address4 address6:address6 error:&err])
    {
        [self closeWithError:err];
    }
}

/**
 * This method is called if the DNS lookup fails.
 * This method is executed on the socketQueue.
 *
 * Since the DNS lookup executed synchronously on a global concurrent queue,
 * the original connection request may have already been cancelled or timed-out by the time this method is invoked.
 * The lookupIndex tells us whether the lookup is still valid or not.
 **/
- (void)lookup:(int)aStateIndex didFail:(NSError *)error
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    
    if (aStateIndex != stateIndex)
    {
        LogInfo(@"Ignoring lookup:didFail: - already disconnected");
        
        // The connect operation has been cancelled.
        // That is, socket was disconnected, or connection has already timed out.
        return;
    }
    
    [self endConnectTimeout];
    [self closeWithError:error];
}

- (BOOL)bindSocket:(int)socketFD toInterface:(NSData *)connectInterface error:(NSError **)errPtr
{
    // Bind the socket to the desired interface (if needed)
    // 若没有指定的本机地址数据，直接return yes，系统会自动绑定一个端口进行连接
    if (connectInterface)
    {
        LogVerbose(@"Binding socket...");
        
        if ([[self class] portFromAddress:connectInterface] > 0)
        {
            // Since we're going to be binding to a specific port,
            // we should turn on reuseaddr to allow us to override sockets in time_wait.
            
            int reuseOn = 1;
            setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        }
        
        const struct sockaddr *interfaceAddr = (const struct sockaddr *)[connectInterface bytes];
        
        int result = bind(socketFD, interfaceAddr, (socklen_t)[connectInterface length]);
        if (result != 0)
        {
            if (errPtr)
                *errPtr = [self errorWithErrno:errno reason:@"Error in bind() function"];
            
            return NO;
        }
    }
    
    return YES;
}

- (int)createSocket:(int)family connectInterface:(NSData *)connectInterface errPtr:(NSError **)errPtr
{
    // 创建socket,用的SOCK_STREAM TCP流
    int socketFD = socket(family, SOCK_STREAM, 0);
    
    if (socketFD == SOCKET_NULL)
    {
        if (errPtr)
            *errPtr = [self errorWithErrno:errno reason:@"Error in socket() function"];
        
        return socketFD;
    }
    
    // 为生成的socket绑定本机地址信息
    if (![self bindSocket:socketFD toInterface:connectInterface error:errPtr])
    {
        [self closeSocket:socketFD];
        
        return SOCKET_NULL;
    }
    
    // Prevent SIGPIPE signals
    // 网路错误后，阻止系统继续发送进程退出的信号
    int nosigpipe = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    
    return socketFD;
}

/**
 使用local socket及server address进行连接
 
 @param socketFD local socket
 @param address server address
 @param aStateIndex state index
 */
- (void)connectSocket:(int)socketFD address:(NSData *)address stateIndex:(int)aStateIndex
{
    // 如果已经有一个套接字连接，我们关闭套接字fd并返回
    if (self.isConnected)
    {
        [self closeSocket:socketFD];
        return;
    }
    
    // socket连接（`connect()`）是阻塞线程的，所以需要在全局并发队列中执行，成功后再返回socketQueue做后续操作
    
    __weak INXAsyncSocket *weakSelf = self;
    
    dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(globalConcurrentQueue, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        int result = connect(socketFD, (const struct sockaddr *)[address bytes], (socklen_t)[address length]);
        int err = errno;
        
        __strong INXAsyncSocket *strongSelf = weakSelf;
        if (strongSelf == nil) return_from_block;
        
        dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
            
            if (strongSelf.isConnected)
            {
                [strongSelf closeSocket:socketFD];
                return_from_block;
            }
            
            if (result == 0)
            {
                [self closeUnusedSocket:socketFD];
                
                [strongSelf didConnect:aStateIndex];
            }
            else
            {
                [strongSelf closeSocket:socketFD];
                
                // 如果没有其他套接字尝试连接，我们将把错误通知委托
                if (strongSelf.socket4FD == SOCKET_NULL && strongSelf.socket6FD == SOCKET_NULL)
                {
                    NSError *error = [strongSelf errorWithErrno:err reason:@"Error in connect() function"];
                    [strongSelf didNotConnect:aStateIndex error:error];
                }
            }
        }});
        
#pragma clang diagnostic pop
    });
    
    LogVerbose(@"Connecting...");
}

- (void)closeSocket:(int)socketFD
{
    if (socketFD != SOCKET_NULL &&
        (socketFD == socket6FD || socketFD == socket4FD))
    {
        close(socketFD);
        
        if (socketFD == socket4FD)
        {
            LogVerbose(@"close(socket4FD)");
            socket4FD = SOCKET_NULL;
        }
        else if (socketFD == socket6FD)
        {
            LogVerbose(@"close(socket6FD)");
            socket6FD = SOCKET_NULL;
        }
    }
}

- (void)closeUnusedSocket:(int)usedSocketFD
{
    if (usedSocketFD != socket4FD)
    {
        [self closeSocket:socket4FD];
    }
    else if (usedSocketFD != socket6FD)
    {
        [self closeSocket:socket6FD];
    }
}

- (BOOL)connectWithAddress4:(NSData *)address4 address6:(NSData *)address6 error:(NSError **)errPtr
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    LogVerbose(@"IPv4: %@:%hu", [[self class] hostFromAddress:address4], [[self class] portFromAddress:address4]);
    LogVerbose(@"IPv6: %@:%hu", [[self class] hostFromAddress:address6], [[self class] portFromAddress:address6]);
    
    // 确定socket类型
    
    BOOL preferIPv6 = (config & kPreferIPv6) ? YES : NO;
    
    // Create and bind the sockets
    // 这里创建的socket是本机的，与server没关系。
    // 这里server的ipv4/ipv6仅仅用来判断是否需要创建对应的本机socket
    // `connectInterface4`和`connectInterface6`为之前生成的本机地址信息
    if (address4)
    {
        LogVerbose(@"Creating IPv4 socket");
        
        socket4FD = [self createSocket:AF_INET connectInterface:connectInterface4 errPtr:errPtr];
    }
    
    if (address6)
    {
        LogVerbose(@"Creating IPv6 socket");
        
        socket6FD = [self createSocket:AF_INET6 connectInterface:connectInterface6 errPtr:errPtr];
    }
    
    if (socket4FD == SOCKET_NULL && socket6FD == SOCKET_NULL)
    {
        return NO;
    }
    
    int socketFD, alternateSocketFD;
    NSData *address, *alternateAddress;
    
    if ((preferIPv6 && socket6FD != SOCKET_NULL) || socket4FD == SOCKET_NULL)
    {
        socketFD = socket6FD;
        alternateSocketFD = socket4FD;
        address = address6;
        alternateAddress = address4;
    }
    else
    {
        socketFD = socket4FD;
        alternateSocketFD = socket6FD;
        address = address4;
        alternateAddress = address6;
    }
    
    int aStateIndex = stateIndex;
    
    [self connectSocket:socketFD address:address stateIndex:aStateIndex];
    
    if (alternateAddress)
    {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(alternateAddressDelay * NSEC_PER_SEC)), socketQueue, ^{
            [self connectSocket:alternateSocketFD address:alternateAddress stateIndex:aStateIndex];
        });
    }
    
    return YES;
}

- (BOOL)connectWithAddressUN:(NSData *)address error:(NSError **)errPtr
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    // Create the socket
    
    int socketFD;
    
    LogVerbose(@"Creating unix domain socket");
    
    socketUN = socket(AF_UNIX, SOCK_STREAM, 0);
    
    socketFD = socketUN;
    
    if (socketFD == SOCKET_NULL)
    {
        if (errPtr)
            *errPtr = [self errorWithErrno:errno reason:@"Error in socket() function"];
        
        return NO;
    }
    
    // Bind the socket to the desired interface (if needed)
    
    LogVerbose(@"Binding socket...");
    
    int reuseOn = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
    
    //    const struct sockaddr *interfaceAddr = (const struct sockaddr *)[address bytes];
    //
    //    int result = bind(socketFD, interfaceAddr, (socklen_t)[address length]);
    //    if (result != 0)
    //    {
    //        if (errPtr)
    //            *errPtr = [self errnoErrorWithReason:@"Error in bind() function"];
    //
    //        return NO;
    //    }
    
    // Prevent SIGPIPE signals
    
    int nosigpipe = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    
    // Start the connection process in a background queue
    
    int aStateIndex = stateIndex;
    
    dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(globalConcurrentQueue, ^{
        
        const struct sockaddr *addr = (const struct sockaddr *)[address bytes];
        int result = connect(socketFD, addr, addr->sa_len);
        if (result == 0)
        {
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                [self didConnect:aStateIndex];
            }});
        }
        else
        {
            // TODO: Bad file descriptor
            perror("connect");
            NSError *error = [self errorWithErrno:errno reason:@"Error in connect() function"];
            
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                [self didNotConnect:aStateIndex error:error];
            }});
        }
    });
    
    LogVerbose(@"Connecting...");
    
    return YES;
}

- (void)didConnect:(int)aStateIndex
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    
    if (aStateIndex != stateIndex)
    {
        LogInfo(@"Ignoring didConnect, already disconnected");
        
        // 连接操作已被取消。也就是说，套接字断开了，或者连接已经超时。
        return;
    }
    
    flags |= kConnected;
    
    [self endConnectTimeout];
    
#if TARGET_OS_IPHONE
    // 上面执行的endConnectTimeout方法增加了状态索引。
    aStateIndex = stateIndex;
#endif
    
    // 设置读/写流(针对iOS平台的特定缺陷)
    //
    // Note:
    // 在打开流之前，委托可能必须设置一些配置选项。
    // 主要的例子是kCFStreamNetworkServiceTypeVoIP标志，它只在未打开的流上工作。
    //
    // 因此，我们要等到套接字:didConnectToHost:port: delegate方法完成之后。
    // 如果需要，这将为委托提供适当的时间来配置流。
    
    // socket连接成功后，打开stream前，必须用相关配置（`kCFStreamNetworkServiceTypeVoIP` etc...）设置代理
    
    dispatch_block_t SetupStreamsPart1 = ^{
#if TARGET_OS_IPHONE
        
        if (![self createReadAndWriteStream])
        {
            [self closeWithError:[self otherError:@"Error creating CFStreams"]];
            return;
        }
        
        if (![self registerForStreamCallbacksIncludingReadWrite:NO])
        {
            [self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
            return;
        }
        
#endif
    };
    dispatch_block_t SetupStreamsPart2 = ^{
#if TARGET_OS_IPHONE
        
        if (aStateIndex != self->stateIndex)
        {
            // The socket has been disconnected.
            return;
        }
        
        if (![self addStreamsToRunLoop])
        {
            [self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
            return;
        }
        
        if (![self openStreams])
        {
            [self closeWithError:[self otherError:@"Error creating CFStreams"]];
            return;
        }
        
#endif
    };
    
    // Notify delegate
    
    NSString *host = [self connectedHost];
    uint16_t port = [self connectedPort];
    NSURL *url = [self connectedUrl];
    
    __strong id theDelegate = delegate;
    
    if (delegateQueue && host != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToHost:port:)])
    {
        SetupStreamsPart1();
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            [theDelegate socket:self didConnectToHost:host port:port];
            
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                SetupStreamsPart2();
            }});
        }});
    }
    else if (delegateQueue && url != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToUrl:)])
    {
        SetupStreamsPart1();
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            [theDelegate socket:self didConnectToUrl:url];
            
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                SetupStreamsPart2();
            }});
        }});
    }
    else
    {
        SetupStreamsPart1();
        SetupStreamsPart2();
    }
    
    // Get the connected socket
    
    int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
    
    // 在套接字上启用非阻塞IO
    
    int result = fcntl(socketFD, F_SETFL, O_NONBLOCK);
    if (result == -1)
    {
        NSString *errMsg = @"Error enabling non-blocking IO on socket (fcntl)";
        [self closeWithError:[self otherError:errMsg]];
        
        return;
    }
    
    // 设置我们的读/写源
    
    [self setupReadAndWriteSourcesForNewlyConnectedSocket:socketFD];
    
    // 删除任何挂起的读/写请求
    
    [self maybeDequeueRead];
    [self maybeDequeueWrite];
}

- (void)didNotConnect:(int)aStateIndex error:(NSError *)error
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    
    if (aStateIndex != stateIndex)
    {
        LogInfo(@"Ignoring didNotConnect, already disconnected");
        
        // 连接操作已被取消。
        // 也就是说，套接字断开了，或者连接已经超时。
        return;
    }
    
    [self closeWithError:error];
}

- (void)startConnectTimeout:(NSTimeInterval)timeout
{
    if (timeout >= 0.0)
    {
        connectTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
        
        __weak INXAsyncSocket *weakSelf = self;
        
        dispatch_source_set_event_handler(connectTimer, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            __strong INXAsyncSocket *strongSelf = weakSelf;
            if (strongSelf == nil) return_from_block;
            
            [strongSelf doConnectTimeout];
            
#pragma clang diagnostic pop
        }});
        
#if !OS_OBJECT_USE_OBJC
        dispatch_source_t theConnectTimer = connectTimer;
        dispatch_source_set_cancel_handler(connectTimer, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            LogVerbose(@"dispatch_release(connectTimer)");
            dispatch_release(theConnectTimer);
            
#pragma clang diagnostic pop
        });
#endif
        
        dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
        dispatch_source_set_timer(connectTimer, tt, DISPATCH_TIME_FOREVER, 0);
        
        dispatch_resume(connectTimer);
    }
}

- (void)endConnectTimeout
{
    LogTrace();
    
    if (connectTimer)
    {
        dispatch_source_cancel(connectTimer);
        connectTimer = NULL;
    }
    
    // Increment stateIndex.
    // 这将阻止我们处理任何相关后台异步操作的结果。
    //
    // 注意:即使connectTimer为空，也应该从close方法调用这个函数。
    // 这是因为可能在没有超时的成功连接之前断开套接字。
    
    stateIndex++;
    
    if (connectInterface4)
    {
        connectInterface4 = nil;
    }
    if (connectInterface6)
    {
        connectInterface6 = nil;
    }
}

- (void)doConnectTimeout
{
    LogTrace();
    
    [self endConnectTimeout];
    [self closeWithError:[self connectTimeoutError]];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Disconnecting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)closeWithError:(NSError *)error
{
    LogTrace();
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    [self endConnectTimeout];
    
    if (currentRead != nil)  [self endCurrentRead];
    if (currentWrite != nil) [self endCurrentWrite];
    
    [readQueue removeAllObjects];
    [writeQueue removeAllObjects];
    
    [preBuffer reset];
    
#if TARGET_OS_IPHONE
    {
        if (readStream || writeStream)
        {
            [self removeStreamsFromRunLoop];
            
            if (readStream)
            {
                CFReadStreamSetClient(readStream, kCFStreamEventNone, NULL, NULL);
                CFReadStreamClose(readStream);
                CFRelease(readStream);
                readStream = NULL;
            }
            if (writeStream)
            {
                CFWriteStreamSetClient(writeStream, kCFStreamEventNone, NULL, NULL);
                CFWriteStreamClose(writeStream);
                CFRelease(writeStream);
                writeStream = NULL;
            }
        }
    }
#endif
    
    [sslPreBuffer reset];
    sslErrCode = lastSSLHandshakeError = noErr;
    
    if (sslContext)
    {
        // 在这里获得关于SSLx()函数的链接器错误?
        // 您需要将安全框架添加到应用程序中。
        
        SSLClose(sslContext);
        
#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
        CFRelease(sslContext);
#else
        SSLDisposeContext(sslContext);
#endif
        
        sslContext = NULL;
    }
    
    // 出于某种疯狂的原因(在我看来)，如果分派源暂停，取消分派源不会调用cancel处理程序。
    // 因此，如果需要，我们必须暂停源。
    // 这允许运行cancel处理程序，该处理程序将释放源并关闭套接字。
    
    if (!accept4Source && !accept6Source && !acceptUNSource && !readSource && !writeSource)
    {
        LogVerbose(@"manually closing close");
        
        if (socket4FD != SOCKET_NULL)
        {
            LogVerbose(@"close(socket4FD)");
            close(socket4FD);
            socket4FD = SOCKET_NULL;
        }
        
        if (socket6FD != SOCKET_NULL)
        {
            LogVerbose(@"close(socket6FD)");
            close(socket6FD);
            socket6FD = SOCKET_NULL;
        }
        
        if (socketUN != SOCKET_NULL)
        {
            LogVerbose(@"close(socketUN)");
            close(socketUN);
            socketUN = SOCKET_NULL;
            unlink(socketUrl.path.fileSystemRepresentation);
            socketUrl = nil;
        }
    }
    else
    {
        if (accept4Source)
        {
            LogVerbose(@"dispatch_source_cancel(accept4Source)");
            dispatch_source_cancel(accept4Source);
            
            // 我们从不暂停accept4Source
            
            accept4Source = NULL;
        }
        
        if (accept6Source)
        {
            LogVerbose(@"dispatch_source_cancel(accept6Source)");
            dispatch_source_cancel(accept6Source);
            
            // 我们从不暂停accept6Source
            
            accept6Source = NULL;
        }
        
        if (acceptUNSource)
        {
            LogVerbose(@"dispatch_source_cancel(acceptUNSource)");
            dispatch_source_cancel(acceptUNSource);
            
            // 我们从不暂停acceptUNSource
            
            acceptUNSource = NULL;
        }
        
        if (readSource)
        {
            LogVerbose(@"dispatch_source_cancel(readSource)");
            dispatch_source_cancel(readSource);
            
            [self resumeReadSource];
            
            readSource = NULL;
        }
        
        if (writeSource)
        {
            LogVerbose(@"dispatch_source_cancel(writeSource)");
            dispatch_source_cancel(writeSource);
            
            [self resumeWriteSource];
            
            writeSource = NULL;
        }
        
        // 套接字将由对应源的cancel处理程序关闭
        
        socket4FD = SOCKET_NULL;
        socket6FD = SOCKET_NULL;
        socketUN = SOCKET_NULL;
    }
    
    // 如果客户端已经通过connect/accept方法，那么连接至少已经开始。
    // 通知委托它现在结束。
    BOOL shouldCallDelegate = (flags & kSocketStarted) ? YES : NO;
    BOOL isDeallocating = (flags & kDealloc) ? YES : NO;
    
    // 清除存储的套接字信息和所有标志(配置保持原样)
    socketFDBytesAvailable = 0;
    flags = 0;
    sslWriteCachedLength = 0;
    
    if (shouldCallDelegate)
    {
        __strong id theDelegate = delegate;
        __strong id theSelf = isDeallocating ? nil : self;
        
        if (delegateQueue && [theDelegate respondsToSelector: @selector(socketDidDisconnect:withError:)])
        {
            dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
                [theDelegate socketDidDisconnect:theSelf withError:error];
            }});
        }
    }
}

- (void)disconnect
{
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if (self->flags & kSocketStarted)
        {
            [self closeWithError:nil];
        }
    }};
    
    // 同步断开，如头文件中记录的那样
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
}

- (void)disconnectAfterReading
{
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        if (self->flags & kSocketStarted)
        {
            self->flags |= (kForbidReadsWrites | kDisconnectAfterReads);
            [self maybeClose];
        }
    }});
}

- (void)disconnectAfterWriting
{
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        if (self->flags & kSocketStarted)
        {
            self->flags |= (kForbidReadsWrites | kDisconnectAfterWrites);
            [self maybeClose];
        }
    }});
}

- (void)disconnectAfterReadingAndWriting
{
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        if (self->flags & kSocketStarted)
        {
            self->flags |= (kForbidReadsWrites | kDisconnectAfterReads | kDisconnectAfterWrites);
            [self maybeClose];
        }
    }});
}

/**
 * 如果可能，关闭套接字。
 * 也就是说，如果所有的写操作都完成了，并且我们在写操作之后被设置为断开连接，
 * 或者如果所有的读操作都完成了，并且我们在读操作之后被设置为断开连接。
 **/
- (void)maybeClose
{
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    BOOL shouldClose = NO;
    
    if (flags & kDisconnectAfterReads)
    {
        if (([readQueue count] == 0) && (currentRead == nil))
        {
            if (flags & kDisconnectAfterWrites)
            {
                if (([writeQueue count] == 0) && (currentWrite == nil))
                {
                    shouldClose = YES;
                }
            }
            else
            {
                shouldClose = YES;
            }
        }
    }
    else if (flags & kDisconnectAfterWrites)
    {
        if (([writeQueue count] == 0) && (currentWrite == nil))
        {
            shouldClose = YES;
        }
    }
    
    if (shouldClose)
    {
        [self closeWithError:nil];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Errors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSError *)badConfigError:(NSString *)errMsg
{
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketBadConfigError userInfo:userInfo];
}

- (NSError *)badParamError:(NSString *)errMsg
{
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketBadParamError userInfo:userInfo];
}

+ (NSError *)gaiError:(int)gai_error
{
    NSString *errMsg = [NSString stringWithCString:gai_strerror(gai_error) encoding:NSASCIIStringEncoding];
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:@"kCFStreamErrorDomainNetDB" code:gai_error userInfo:userInfo];
}

- (NSError *)errorWithErrno:(int)err reason:(NSString *)reason
{
    NSString *errMsg = [NSString stringWithUTF8String:strerror(err)];
    NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:errMsg, NSLocalizedDescriptionKey,
                              reason, NSLocalizedFailureReasonErrorKey, nil];
    
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:err userInfo:userInfo];
}

- (NSError *)errnoError
{
    NSString *errMsg = [NSString stringWithUTF8String:strerror(errno)];
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:userInfo];
}

- (NSError *)sslError:(OSStatus)ssl_error
{
    NSString *msg = @"Error code definition can be found in Apple's SecureTransport.h";
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:msg forKey:NSLocalizedRecoverySuggestionErrorKey];
    
    return [NSError errorWithDomain:@"kCFStreamErrorDomainSSL" code:ssl_error userInfo:userInfo];
}

- (NSError *)connectTimeoutError
{
    NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketConnectTimeoutError",
                                                         @"INXAsyncSocket", [NSBundle mainBundle],
                                                         @"Attempt to connect to host timed out", nil);
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketConnectTimeoutError userInfo:userInfo];
}

/**
 * 返回一个标准的AsyncSocket最大化错误。
 **/
- (NSError *)readMaxedOutError
{
    NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketReadMaxedOutError",
                                                         @"INXAsyncSocket", [NSBundle mainBundle],
                                                         @"Read operation reached set maximum length", nil);
    
    NSDictionary *info = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketReadMaxedOutError userInfo:info];
}

/**
 * 返回一个标准的AsyncSocket读超时错误。
 **/
- (NSError *)readTimeoutError
{
    NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketReadTimeoutError",
                                                         @"INXAsyncSocket", [NSBundle mainBundle],
                                                         @"Read operation timed out", nil);
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketReadTimeoutError userInfo:userInfo];
}

/**
 * 返回一个标准的AsyncSocket写超时错误。
 **/
- (NSError *)writeTimeoutError
{
    NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketWriteTimeoutError",
                                                         @"INXAsyncSocket", [NSBundle mainBundle],
                                                         @"Write operation timed out", nil);
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketWriteTimeoutError userInfo:userInfo];
}

- (NSError *)connectionClosedError
{
    NSString *errMsg = NSLocalizedStringWithDefaultValue(@"INXAsyncSocketClosedError",
                                                         @"INXAsyncSocket", [NSBundle mainBundle],
                                                         @"Socket closed by remote peer", nil);
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketClosedError userInfo:userInfo];
}

- (NSError *)otherError:(NSString *)errMsg
{
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
    
    return [NSError errorWithDomain:INXAsyncSocketErrorDomain code:INXAsyncSocketOtherError userInfo:userInfo];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Diagnostics
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (BOOL)isDisconnected
{
    __block BOOL result = NO;
    
    dispatch_block_t block = ^{
        result = (self->flags & kSocketStarted) ? NO : YES;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

- (BOOL)isConnected
{
    __block BOOL result = NO;
    
    dispatch_block_t block = ^{
        result = (self->flags & kConnected) ? YES : NO;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

- (NSString *)connectedHost
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (socket4FD != SOCKET_NULL)
            return [self connectedHostFromSocket4:socket4FD];
        if (socket6FD != SOCKET_NULL)
            return [self connectedHostFromSocket6:socket6FD];
        
        return nil;
    }
    else
    {
        __block NSString *result = nil;
        
        dispatch_sync(socketQueue, ^{ @autoreleasepool {
            
            if (self->socket4FD != SOCKET_NULL)
                result = [self connectedHostFromSocket4:self->socket4FD];
            else if (self->socket6FD != SOCKET_NULL)
                result = [self connectedHostFromSocket6:self->socket6FD];
        }});
        
        return result;
    }
}

- (uint16_t)connectedPort
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (socket4FD != SOCKET_NULL)
            return [self connectedPortFromSocket4:socket4FD];
        if (socket6FD != SOCKET_NULL)
            return [self connectedPortFromSocket6:socket6FD];
        
        return 0;
    }
    else
    {
        __block uint16_t result = 0;
        
        dispatch_sync(socketQueue, ^{
            // No need for autorelease pool
            
            if (self->socket4FD != SOCKET_NULL)
                result = [self connectedPortFromSocket4:self->socket4FD];
            else if (self->socket6FD != SOCKET_NULL)
                result = [self connectedPortFromSocket6:self->socket6FD];
        });
        
        return result;
    }
}

- (NSURL *)connectedUrl
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (socketUN != SOCKET_NULL)
            return [self connectedUrlFromSocketUN:socketUN];
        
        return nil;
    }
    else
    {
        __block NSURL *result = nil;
        
        dispatch_sync(socketQueue, ^{ @autoreleasepool {
            
            if (self->socketUN != SOCKET_NULL)
                result = [self connectedUrlFromSocketUN:self->socketUN];
        }});
        
        return result;
    }
}

- (NSString *)localHost
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (socket4FD != SOCKET_NULL)
            return [self localHostFromSocket4:socket4FD];
        if (socket6FD != SOCKET_NULL)
            return [self localHostFromSocket6:socket6FD];
        
        return nil;
    }
    else
    {
        __block NSString *result = nil;
        
        dispatch_sync(socketQueue, ^{ @autoreleasepool {
            
            if (self->socket4FD != SOCKET_NULL)
                result = [self localHostFromSocket4:self->socket4FD];
            else if (self->socket6FD != SOCKET_NULL)
                result = [self localHostFromSocket6:self->socket6FD];
        }});
        
        return result;
    }
}

- (uint16_t)localPort
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        if (socket4FD != SOCKET_NULL)
            return [self localPortFromSocket4:socket4FD];
        if (socket6FD != SOCKET_NULL)
            return [self localPortFromSocket6:socket6FD];
        
        return 0;
    }
    else
    {
        __block uint16_t result = 0;
        
        dispatch_sync(socketQueue, ^{
            // No need for autorelease pool
            
            if (self->socket4FD != SOCKET_NULL)
                result = [self localPortFromSocket4:self->socket4FD];
            else if (self->socket6FD != SOCKET_NULL)
                result = [self localPortFromSocket6:self->socket6FD];
        });
        
        return result;
    }
}

- (NSString *)connectedHost4
{
    if (socket4FD != SOCKET_NULL)
        return [self connectedHostFromSocket4:socket4FD];
    
    return nil;
}

- (NSString *)connectedHost6
{
    if (socket6FD != SOCKET_NULL)
        return [self connectedHostFromSocket6:socket6FD];
    
    return nil;
}

- (uint16_t)connectedPort4
{
    if (socket4FD != SOCKET_NULL)
        return [self connectedPortFromSocket4:socket4FD];
    
    return 0;
}

- (uint16_t)connectedPort6
{
    if (socket6FD != SOCKET_NULL)
        return [self connectedPortFromSocket6:socket6FD];
    
    return 0;
}

- (NSString *)localHost4
{
    if (socket4FD != SOCKET_NULL)
        return [self localHostFromSocket4:socket4FD];
    
    return nil;
}

- (NSString *)localHost6
{
    if (socket6FD != SOCKET_NULL)
        return [self localHostFromSocket6:socket6FD];
    
    return nil;
}

- (uint16_t)localPort4
{
    if (socket4FD != SOCKET_NULL)
        return [self localPortFromSocket4:socket4FD];
    
    return 0;
}

- (uint16_t)localPort6
{
    if (socket6FD != SOCKET_NULL)
        return [self localPortFromSocket6:socket6FD];
    
    return 0;
}

- (NSString *)connectedHostFromSocket4:(int)socketFD
{
    struct sockaddr_in sockaddr4;
    socklen_t sockaddr4len = sizeof(sockaddr4);
    
    if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
    {
        return nil;
    }
    return [[self class] hostFromSockaddr4:&sockaddr4];
}

- (NSString *)connectedHostFromSocket6:(int)socketFD
{
    struct sockaddr_in6 sockaddr6;
    socklen_t sockaddr6len = sizeof(sockaddr6);
    
    if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
    {
        return nil;
    }
    return [[self class] hostFromSockaddr6:&sockaddr6];
}

- (uint16_t)connectedPortFromSocket4:(int)socketFD
{
    struct sockaddr_in sockaddr4;
    socklen_t sockaddr4len = sizeof(sockaddr4);
    
    if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
    {
        return 0;
    }
    return [[self class] portFromSockaddr4:&sockaddr4];
}

- (uint16_t)connectedPortFromSocket6:(int)socketFD
{
    struct sockaddr_in6 sockaddr6;
    socklen_t sockaddr6len = sizeof(sockaddr6);
    
    if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
    {
        return 0;
    }
    return [[self class] portFromSockaddr6:&sockaddr6];
}

- (NSURL *)connectedUrlFromSocketUN:(int)socketFD
{
    struct sockaddr_un sockaddr;
    socklen_t sockaddrlen = sizeof(sockaddr);
    
    if (getpeername(socketFD, (struct sockaddr *)&sockaddr, &sockaddrlen) < 0)
    {
        return 0;
    }
    return [[self class] urlFromSockaddrUN:&sockaddr];
}

- (NSString *)localHostFromSocket4:(int)socketFD
{
    struct sockaddr_in sockaddr4;
    socklen_t sockaddr4len = sizeof(sockaddr4);
    
    if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
    {
        return nil;
    }
    return [[self class] hostFromSockaddr4:&sockaddr4];
}

- (NSString *)localHostFromSocket6:(int)socketFD
{
    struct sockaddr_in6 sockaddr6;
    socklen_t sockaddr6len = sizeof(sockaddr6);
    
    if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
    {
        return nil;
    }
    return [[self class] hostFromSockaddr6:&sockaddr6];
}

- (uint16_t)localPortFromSocket4:(int)socketFD
{
    struct sockaddr_in sockaddr4;
    socklen_t sockaddr4len = sizeof(sockaddr4);
    
    if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
    {
        return 0;
    }
    return [[self class] portFromSockaddr4:&sockaddr4];
}

- (uint16_t)localPortFromSocket6:(int)socketFD
{
    struct sockaddr_in6 sockaddr6;
    socklen_t sockaddr6len = sizeof(sockaddr6);
    
    if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
    {
        return 0;
    }
    return [[self class] portFromSockaddr6:&sockaddr6];
}

- (NSData *)connectedAddress
{
    __block NSData *result = nil;
    
    dispatch_block_t block = ^{
        if (self->socket4FD != SOCKET_NULL)
        {
            struct sockaddr_in sockaddr4;
            socklen_t sockaddr4len = sizeof(sockaddr4);
            
            if (getpeername(self->socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
            {
                result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
            }
        }
        
        if (self->socket6FD != SOCKET_NULL)
        {
            struct sockaddr_in6 sockaddr6;
            socklen_t sockaddr6len = sizeof(sockaddr6);
            
            if (getpeername(self->socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
            {
                result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
            }
        }
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

- (NSData *)localAddress
{
    __block NSData *result = nil;
    
    dispatch_block_t block = ^{
        if (self->socket4FD != SOCKET_NULL)
        {
            struct sockaddr_in sockaddr4;
            socklen_t sockaddr4len = sizeof(sockaddr4);
            
            if (getsockname(self->socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
            {
                result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
            }
        }
        
        if (self->socket6FD != SOCKET_NULL)
        {
            struct sockaddr_in6 sockaddr6;
            socklen_t sockaddr6len = sizeof(sockaddr6);
            
            if (getsockname(self->socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
            {
                result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
            }
        }
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

- (BOOL)isIPv4
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return (socket4FD != SOCKET_NULL);
    }
    else
    {
        __block BOOL result = NO;
        
        dispatch_sync(socketQueue, ^{
            result = (self->socket4FD != SOCKET_NULL);
        });
        
        return result;
    }
}

- (BOOL)isIPv6
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return (socket6FD != SOCKET_NULL);
    }
    else
    {
        __block BOOL result = NO;
        
        dispatch_sync(socketQueue, ^{
            result = (self->socket6FD != SOCKET_NULL);
        });
        
        return result;
    }
}

- (BOOL)isSecure
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return (flags & kSocketSecure) ? YES : NO;
    }
    else
    {
        __block BOOL result;
        
        dispatch_sync(socketQueue, ^{
            result = (self->flags & kSocketSecure) ? YES : NO;
        });
        
        return result;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * 查找接口描述的地址。
 * 接口描述可以是接口名(en0、en1、lo0)或相应的IP(192.168.4.34)。
 *
 * 接口描述可以选择在末尾包含端口号，端口号之间用冒号分隔。
 * 如果提供非零端口参数，则忽略接口描述中的任何端口号。
 *
 * 返回的值是一个封装在NSMutableData对象中的“struct sockaddr”。
 **/
- (void)getInterfaceAddress4:(NSMutableData **)interfaceAddr4Ptr
                    address6:(NSMutableData **)interfaceAddr6Ptr
             fromDescription:(NSString *)interfaceDescription
                        port:(uint16_t)port
{
    NSMutableData *addr4 = nil;
    NSMutableData *addr6 = nil;
    
    NSString *interface = nil;
    
    NSArray *components = [interfaceDescription componentsSeparatedByString:@":"];
    if ([components count] > 0)
    {
        NSString *temp = [components objectAtIndex:0];
        if ([temp length] > 0)
        {
            interface = temp;
        }
    }
    if ([components count] > 1 && port == 0)
    {
        long portL = strtol([[components objectAtIndex:1] UTF8String], NULL, 10);
        
        if (portL > 0 && portL <= UINT16_MAX)
        {
            port = (uint16_t)portL;
        }
    }
    
    if (interface == nil)
    {
        // ANY address
        
        struct sockaddr_in sockaddr4;
        memset(&sockaddr4, 0, sizeof(sockaddr4));
        
        sockaddr4.sin_len         = sizeof(sockaddr4);
        sockaddr4.sin_family      = AF_INET;
        sockaddr4.sin_port        = htons(port);
        sockaddr4.sin_addr.s_addr = htonl(INADDR_ANY);
        
        struct sockaddr_in6 sockaddr6;
        memset(&sockaddr6, 0, sizeof(sockaddr6));
        
        sockaddr6.sin6_len       = sizeof(sockaddr6);
        sockaddr6.sin6_family    = AF_INET6;
        sockaddr6.sin6_port      = htons(port);
        sockaddr6.sin6_addr      = in6addr_any;
        
        addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
        addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
    }
    else if ([interface isEqualToString:@"localhost"] || [interface isEqualToString:@"loopback"])
    {
        // LOOPBACK address
        
        struct sockaddr_in sockaddr4;
        memset(&sockaddr4, 0, sizeof(sockaddr4));
        
        sockaddr4.sin_len         = sizeof(sockaddr4);
        sockaddr4.sin_family      = AF_INET;
        sockaddr4.sin_port        = htons(port);
        sockaddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        
        struct sockaddr_in6 sockaddr6;
        memset(&sockaddr6, 0, sizeof(sockaddr6));
        
        sockaddr6.sin6_len       = sizeof(sockaddr6);
        sockaddr6.sin6_family    = AF_INET6;
        sockaddr6.sin6_port      = htons(port);
        sockaddr6.sin6_addr      = in6addr_loopback;
        
        addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
        addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
    }
    else
    {
        const char *iface = [interface UTF8String];
        
        struct ifaddrs *addrs;
        const struct ifaddrs *cursor;
        
        if ((getifaddrs(&addrs) == 0))
        {
            cursor = addrs;
            while (cursor != NULL)
            {
                if ((addr4 == nil) && (cursor->ifa_addr->sa_family == AF_INET))
                {
                    // IPv4
                    
                    struct sockaddr_in nativeAddr4;
                    memcpy(&nativeAddr4, cursor->ifa_addr, sizeof(nativeAddr4));
                    
                    if (strcmp(cursor->ifa_name, iface) == 0)
                    {
                        // Name match
                        
                        nativeAddr4.sin_port = htons(port);
                        
                        addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
                    }
                    else
                    {
                        char ip[INET_ADDRSTRLEN];
                        
                        const char *conversion = inet_ntop(AF_INET, &nativeAddr4.sin_addr, ip, sizeof(ip));
                        
                        if ((conversion != NULL) && (strcmp(ip, iface) == 0))
                        {
                            // IP match
                            
                            nativeAddr4.sin_port = htons(port);
                            
                            addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
                        }
                    }
                }
                else if ((addr6 == nil) && (cursor->ifa_addr->sa_family == AF_INET6))
                {
                    // IPv6
                    
                    struct sockaddr_in6 nativeAddr6;
                    memcpy(&nativeAddr6, cursor->ifa_addr, sizeof(nativeAddr6));
                    
                    if (strcmp(cursor->ifa_name, iface) == 0)
                    {
                        // Name match
                        
                        nativeAddr6.sin6_port = htons(port);
                        
                        addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
                    }
                    else
                    {
                        char ip[INET6_ADDRSTRLEN];
                        
                        const char *conversion = inet_ntop(AF_INET6, &nativeAddr6.sin6_addr, ip, sizeof(ip));
                        
                        if ((conversion != NULL) && (strcmp(ip, iface) == 0))
                        {
                            // IP match
                            
                            nativeAddr6.sin6_port = htons(port);
                            
                            addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
                        }
                    }
                }
                
                cursor = cursor->ifa_next;
            }
            
            freeifaddrs(addrs);
        }
    }
    
    if (interfaceAddr4Ptr) *interfaceAddr4Ptr = addr4;
    if (interfaceAddr6Ptr) *interfaceAddr6Ptr = addr6;
}

- (NSData *)getInterfaceAddressFromUrl:(NSURL *)url;
{
    NSString *path = url.path;
    if (path.length == 0) {
        return nil;
    }
    
    struct sockaddr_un nativeAddr;
    nativeAddr.sun_family = AF_UNIX;
    strlcpy(nativeAddr.sun_path, path.fileSystemRepresentation, sizeof(nativeAddr.sun_path));
    nativeAddr.sun_len = (unsigned char)SUN_LEN(&nativeAddr);
    NSData *interface = [NSData dataWithBytes:&nativeAddr length:sizeof(struct sockaddr_un)];
    
    return interface;
}


/**
 所有的消息都是由这个source来触发
 
 @param socketFD 需要设置source的socket
 */
- (void)setupReadAndWriteSourcesForNewlyConnectedSocket:(int)socketFD
{
    readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socketFD, 0, socketQueue);
    writeSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, socketFD, 0, socketQueue);
    
    // Setup event handlers
    
    __weak INXAsyncSocket *weakSelf = self;
    
    dispatch_source_set_event_handler(readSource, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        __strong INXAsyncSocket *strongSelf = weakSelf;
        if (strongSelf == nil) return_from_block;
        
        LogVerbose(@"readEventBlock");
        
        strongSelf->socketFDBytesAvailable = dispatch_source_get_data(strongSelf->readSource);
        LogVerbose(@"socketFDBytesAvailable: %lu", strongSelf->socketFDBytesAvailable);
        
        if (strongSelf->socketFDBytesAvailable > 0)
            [strongSelf doReadData];
        else
            [strongSelf doReadEOF];
        
#pragma clang diagnostic pop
    }});
    
    dispatch_source_set_event_handler(writeSource, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        __strong INXAsyncSocket *strongSelf = weakSelf;
        if (strongSelf == nil) return_from_block;
        
        LogVerbose(@"writeEventBlock");
        
        strongSelf->flags |= kSocketCanAcceptBytes;
        [strongSelf doWriteData];
        
#pragma clang diagnostic pop
    }});
    
    // Setup cancel handlers
    
    __block int socketFDRefCount = 2;
    
#if !OS_OBJECT_USE_OBJC
    dispatch_source_t theReadSource = readSource;
    dispatch_source_t theWriteSource = writeSource;
#endif
    
    dispatch_source_set_cancel_handler(readSource, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        LogVerbose(@"readCancelBlock");
        
#if !OS_OBJECT_USE_OBJC
        LogVerbose(@"dispatch_release(readSource)");
        dispatch_release(theReadSource);
#endif
        
        if (--socketFDRefCount == 0)
        {
            LogVerbose(@"close(socketFD)");
            close(socketFD);
        }
        
#pragma clang diagnostic pop
    });
    
    dispatch_source_set_cancel_handler(writeSource, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        LogVerbose(@"writeCancelBlock");
        
#if !OS_OBJECT_USE_OBJC
        LogVerbose(@"dispatch_release(writeSource)");
        dispatch_release(theWriteSource);
#endif
        
        if (--socketFDRefCount == 0)
        {
            LogVerbose(@"close(socketFD)");
            close(socketFD);
        }
        
#pragma clang diagnostic pop
    });
    
    // 直到数据到达，我们才能够阅读。
    // 但是我们应该能够立即写出来。
    
    socketFDBytesAvailable = 0;
    flags &= ~kReadSourceSuspended;
    
    LogVerbose(@"dispatch_resume(readSource)");
    dispatch_resume(readSource);
    
    flags |= kSocketCanAcceptBytes;
    flags |= kWriteSourceSuspended;
}

- (BOOL)usingCFStreamForTLS
{
#if TARGET_OS_IPHONE
    
    if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
    {
        // startTLS方法被赋予INXAsyncSocketUseCFStreamForTLS标志。
        
        return YES;
    }
    
#endif
    
    return NO;
}

- (BOOL)usingSecureTransportForTLS
{
    // 调用这个方法等价于![self usingCFStreamForTLS](只是可读性更好)
    
#if TARGET_OS_IPHONE
    
    if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
    {
        // startTLS方法被赋予INXAsyncSocketUseCFStreamForTLS标志。
        
        return NO;
    }
    
#endif
    
    return YES;
}

- (void)suspendReadSource
{
    if (!(flags & kReadSourceSuspended))
    {
        LogVerbose(@"dispatch_suspend(readSource)");
        
        dispatch_suspend(readSource);
        flags |= kReadSourceSuspended;
    }
}

- (void)resumeReadSource
{
    if (flags & kReadSourceSuspended)
    {
        LogVerbose(@"dispatch_resume(readSource)");
        
        dispatch_resume(readSource);
        flags &= ~kReadSourceSuspended;
    }
}

- (void)suspendWriteSource
{
    if (!(flags & kWriteSourceSuspended))
    {
        LogVerbose(@"dispatch_suspend(writeSource)");
        
        dispatch_suspend(writeSource);
        flags |= kWriteSourceSuspended;
    }
}

- (void)resumeWriteSource
{
    if (flags & kWriteSourceSuspended)
    {
        LogVerbose(@"dispatch_resume(writeSource)");
        
        dispatch_resume(writeSource);
        flags &= ~kWriteSourceSuspended;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Reading
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)readDataWithTimeout:(NSTimeInterval)timeout tag:(long)tag
{
    [self readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                        tag:(long)tag
{
    [self readDataWithTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                  maxLength:(NSUInteger)length
                        tag:(long)tag
{
    if (offset > [buffer length]) {
        LogWarn(@"Cannot read: offset > [buffer length]");
        return;
    }
    
    INXAsyncReadPacket *packet = [[INXAsyncReadPacket alloc] initWithData:buffer
                                                              startOffset:offset
                                                                maxLength:length
                                                                  timeout:timeout
                                                               readLength:0
                                                               terminator:nil
                                                                      tag:tag];
    
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        LogTrace();
        
        if ((self->flags & kSocketStarted) && !(self->flags & kForbidReadsWrites))
        {
            [self->readQueue addObject:packet];
            [self maybeDequeueRead];
        }
    }});
    
    // 不要依赖正在运行的块来释放packet，因为队列可能在没有完成块的情况下被释放。
}

- (void)readDataToLength:(NSUInteger)length withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
    [self readDataToLength:length withTimeout:timeout buffer:nil bufferOffset:0 tag:tag];
}

- (void)readDataToLength:(NSUInteger)length
             withTimeout:(NSTimeInterval)timeout
                  buffer:(NSMutableData *)buffer
            bufferOffset:(NSUInteger)offset
                     tag:(long)tag
{
    if (length == 0) {
        LogWarn(@"Cannot read: length == 0");
        return;
    }
    if (offset > [buffer length]) {
        LogWarn(@"Cannot read: offset > [buffer length]");
        return;
    }
    
    INXAsyncReadPacket *packet = [[INXAsyncReadPacket alloc] initWithData:buffer
                                                              startOffset:offset
                                                                maxLength:0
                                                                  timeout:timeout
                                                               readLength:length
                                                               terminator:nil
                                                                      tag:tag];
    
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        LogTrace();
        
        if ((self->flags & kSocketStarted) && !(self->flags & kForbidReadsWrites))
        {
            [self->readQueue addObject:packet];
            [self maybeDequeueRead];
        }
    }});
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
    [self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
                   tag:(long)tag
{
    [self readDataToData:data withTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag
{
    [self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:length tag:tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
             maxLength:(NSUInteger)maxLength
                   tag:(long)tag
{
    if ([data length] == 0) {
        LogWarn(@"Cannot read: [data length] == 0");
        return;
    }
    if (offset > [buffer length]) {
        LogWarn(@"Cannot read: offset > [buffer length]");
        return;
    }
    if (maxLength > 0 && maxLength < [data length]) {
        LogWarn(@"Cannot read: maxLength > 0 && maxLength < [data length]");
        return;
    }
    
    INXAsyncReadPacket *packet = [[INXAsyncReadPacket alloc] initWithData:buffer
                                                              startOffset:offset
                                                                maxLength:maxLength
                                                                  timeout:timeout
                                                               readLength:0
                                                               terminator:data
                                                                      tag:tag];
    
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        LogTrace();
        
        if ((self->flags & kSocketStarted) && !(self->flags & kForbidReadsWrites))
        {
            [self->readQueue addObject:packet];
            [self maybeDequeueRead];
        }
    }});
}

- (float)progressOfReadReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
    __block float result = 0.0F;
    
    dispatch_block_t block = ^{
        
        if (!self->currentRead || ![self->currentRead isKindOfClass:[INXAsyncReadPacket class]])
        {
            // 我们现在什么都没读。
            
            if (tagPtr != NULL)   *tagPtr = 0;
            if (donePtr != NULL)  *donePtr = 0;
            if (totalPtr != NULL) *totalPtr = 0;
            
            result = NAN;
        }
        else
        {
            // 只有当我们读到一定的长度时，才有可能知道我们的阅读进度。
            // 如果我们读数据，我们当然不知道数据何时到达。
            // 如果我们读取超时，那么我们不知道下一个数据块何时到达。
            
            NSUInteger done = self->currentRead->bytesDone;
            NSUInteger total = self->currentRead->readLength;
            
            if (tagPtr != NULL)   *tagPtr = self->currentRead->tag;
            if (donePtr != NULL)  *donePtr = done;
            if (totalPtr != NULL) *totalPtr = total;
            
            if (total > 0)
                result = (float)done / (float)total;
            else
                result = 1.0F;
        }
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

/**
 * 如果需要，此方法将启动新的读取。
 *
 * 当:
 *  -用户请求读取
 *  -读取请求完成后(处理下一个请求)
 *  -在套接字打开后立即处理任何挂起的请求
 *
 * 此方法还处理自动断开后读/写完成。
 **/
- (void)maybeDequeueRead
{
    LogTrace();
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    // 如果我们当前没有处理读操作，而我们有一个可用的读流
    if ((currentRead == nil) && (flags & kConnected))
    {
        if ([readQueue count] > 0)
        {
            // Dequeue the next object in the write queue
            currentRead = [readQueue objectAtIndex:0];
            [readQueue removeObjectAtIndex:0];
            
            
            if ([currentRead isKindOfClass:[INXAsyncSpecialPacket class]])
            {
                LogVerbose(@"Dequeued INXAsyncSpecialPacket");
                
                // 尝试启动TLS
                flags |= kStartingReadTLS;
                
                // 除非设置了kStartingReadTLS和kStartingWriteTLS，否则此方法不会执行任何操作
                [self maybeStartTLS];
            }
            else
            {
                LogVerbose(@"Dequeued INXAsyncReadPacket");
                
                // 设置读取计时器(如果需要)
                [self setupReadTimerWithTimeout:currentRead->timeout];
                
                // 如果可能，立即阅读
                [self doReadData];
            }
        }
        else if (flags & kDisconnectAfterReads)
        {
            if (flags & kDisconnectAfterWrites)
            {
                if (([writeQueue count] == 0) && (currentWrite == nil))
                {
                    [self closeWithError:nil];
                }
            }
            else
            {
                [self closeWithError:nil];
            }
        }
        else if (flags & kSocketSecure)
        {
            [self flushSSLBuffers];
            
            // Edge case:
            //
            // 我们刚刚从ssl缓冲区中取出所有数据，
            // 以及套接字中的所有已知数据(socketFDBytesAvailable)。
            //
            // 如果我们没有从这个过程中获得任何数据，那么我们可能已经到达TCP流的末尾。
            //
            // 确保已启用回调，以便在断开连接时通知我们。
            
            if ([preBuffer availableBytes] == 0)
            {
                if ([self usingCFStreamForTLS]) {
                    // Callbacks never disabled
                }
                else {
                    [self resumeReadSource];
                }
            }
        }
    }
}

- (void)flushSSLBuffers
{
    LogTrace();
    
    NSAssert((flags & kSocketSecure), @"Cannot flush ssl buffers on non-secure socket");
    
    if ([preBuffer availableBytes] > 0)
    {
        // 只在预缓冲区为空时刷新ssl缓冲区。
        // 这是为了避免将预缓冲区增长得非常大。
        
        return;
    }
    
#if TARGET_OS_IPHONE
    
    if ([self usingCFStreamForTLS])
    {
        if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
        {
            LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
            
            CFIndex defaultBytesToRead = (1024 * 4);
            
            [preBuffer ensureCapacityForWrite:defaultBytesToRead];
            
            uint8_t *buffer = [preBuffer writeBuffer];
            
            CFIndex result = CFReadStreamRead(readStream, buffer, defaultBytesToRead);
            LogVerbose(@"%@ - CFReadStreamRead(): result = %i", THIS_METHOD, (int)result);
            
            if (result > 0)
            {
                [preBuffer didWrite:result];
            }
            
            flags &= ~kSecureSocketHasBytesAvailable;
        }
        
        return;
    }
    
#endif
    
    __block NSUInteger estimatedBytesAvailable = 0;
    
    dispatch_block_t updateEstimatedBytesAvailable = ^{
        
        // 弄清楚是否有可用的数据可供读取
        //
        // socketFDBytesAvailable        <- 未从bsd套接字读取的加密字节数
        // [sslPreBuffer availableBytes] <- 从bsd套接字缓存的加密字节数
        // sslInternalBufSize            <- 安全传输已缓存的解密字节数
        //
        // 我们将变量称为“estimate”，因为我们不知道从sslPreBuffer中的加密字节中会得到多少解密字节。
        // 然而，我们知道这是估计的上限。
        
        estimatedBytesAvailable = self->socketFDBytesAvailable + [self->sslPreBuffer availableBytes];
        
        size_t sslInternalBufSize = 0;
        SSLGetBufferedReadSize(self->sslContext, &sslInternalBufSize);
        
        estimatedBytesAvailable += sslInternalBufSize;
    };
    
    updateEstimatedBytesAvailable();
    
    if (estimatedBytesAvailable > 0)
    {
        LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
        
        BOOL done = NO;
        do
        {
            LogVerbose(@"%@ - estimatedBytesAvailable = %lu", THIS_METHOD, (unsigned long)estimatedBytesAvailable);
            
            // 确保预缓冲器有足够的空间
            
            [preBuffer ensureCapacityForWrite:estimatedBytesAvailable];
            
            // 将数据读入预缓冲区
            
            uint8_t *buffer = [preBuffer writeBuffer];
            size_t bytesRead = 0;
            
            OSStatus result = SSLRead(sslContext, buffer, (size_t)estimatedBytesAvailable, &bytesRead);
            LogVerbose(@"%@ - read from secure socket = %u", THIS_METHOD, (unsigned)bytesRead);
            
            if (bytesRead > 0)
            {
                [preBuffer didWrite:bytesRead];
            }
            
            LogVerbose(@"%@ - prebuffer.length = %zu", THIS_METHOD, [preBuffer availableBytes]);
            
            if (result != noErr)
            {
                done = YES;
            }
            else
            {
                updateEstimatedBytesAvailable();
            }
            
        } while (!done && estimatedBytesAvailable > 0);
    }
}

- (void)doReadData
{
    LogTrace();
    
    // 这个方法是在socketQueue上调用的。
    // 当数据可用时，可以直接调用它，或者通过readSource调用它。
    
    if ((currentRead == nil) || (flags & kReadsPaused))
    {
        LogVerbose(@"No currentRead or kReadsPaused");
        
        // 这时不可以读取数据
        
        if (flags & kSocketSecure)
        {
            // 场景如下：
            //
            // 我们已经建立了安全连接。
            // 可能没有currentRead，但可能有加密的数据为我们保留。
            // 当用户开始执行读取操作时，需要对加密的数据进行解密
            //
            // 那么为什么要让用户等待呢?
            // 我们最好现在就开始解密一些数据。
            //
            // 我们这样做的另一个原因是检测套接字断开。
            // SSL/TLS协议有自己的断开连接握手。
            // 因此，当一个安全套接字被关闭时，一个“再见”包就会通过网络出现。
            // 我们要确保读取了“goodbye”包，以便能够正确地检测TCP断开。
            
            [self flushSSLBuffers];
        }
        
        if ([self usingCFStreamForTLS])
        {
            // CFReadStream只在有可用数据时触发一次。
            // 在调用CFReadStreamRead之前，它不会再次触发。
        }
        else
        {
            // 如果readSource正在触发，我们需要暂停它，否则它将继续一次又一次地触发。
            //
            // 如果readSource没有触发，我们希望它继续监视套接字。
            
            if (socketFDBytesAvailable > 0)
            {
                [self suspendReadSource];
            }
        }
        return;
    }
    
    BOOL hasBytesAvailable = NO;
    unsigned long estimatedBytesAvailable = 0;
    
    if ([self usingCFStreamForTLS])
    {
#if TARGET_OS_IPHONE
        
        // 为TLS请求CFStream，而不是SecureTransport(通过INXAsyncSocketUseCFStreamForTLS)
        
        estimatedBytesAvailable = 0;
        if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
            hasBytesAvailable = YES;
        else
            hasBytesAvailable = NO;
        
#endif
    }
    else
    {
        estimatedBytesAvailable = socketFDBytesAvailable;
        
        if (flags & kSocketSecure)
        {
            // 这里需要注意两个缓冲区。
            //
            // 我们使用的是SecureTransport，一个位于TCP之上的TLS/SSL安全层。
            // 我们向SecureTranport API发出一个读，而SecureTranport API又向我们的SSLReadFunction发出一个读。
            // 然后，我们的SSLReadFunction从BSD套接字中读取数据，并返回加密的数据以安全地重新传输。
            // SecureTransport然后解密数据，最后将解密后的数据返回给我们。
            //
            // 第一个缓冲区是我们创建的。
            // SecureTransport通常需要少量数据。
            // 这与来自TCP流的 encypted packets 有关。
            // 但是从BSD套接字执行一些小的读取不是最优的。
            // 因此，我们的SSLReadFunction从套接字读取所有可用的数据(优化sys调用)，并可能将多余的数据存储在sslPreBuffer中。
            
            estimatedBytesAvailable += [sslPreBuffer availableBytes];
            
            // 第二个缓冲区在SecureTransport中。
            // 如前所述，TCP流中有加密的数据包。
            // SecureTransport需要整个数据包来解密它。
            // 但是如果整个数据包产生X字节的解密数据，
            // 我们只要求安全传输X/2字节的数据，
            // 它必须存储额外的X/2字节的解密数据，以便下一次读取。
            //
            // SSLGetBufferedReadSize函数将告诉我们这个内部缓冲区的大小。
            // 从文档:
            //
            // “此函数不会阻塞或导致任何低级读取操作发生。”
            
            size_t sslInternalBufSize = 0;
            SSLGetBufferedReadSize(sslContext, &sslInternalBufSize);
            
            estimatedBytesAvailable += sslInternalBufSize;
        }
        
        hasBytesAvailable = (estimatedBytesAvailable > 0);
    }
    
    if ((hasBytesAvailable == NO) && ([preBuffer availableBytes] == 0))
    {
        LogVerbose(@"No data available to read...");
        
        // No data available to read.
        
        if (![self usingCFStreamForTLS])
        {
            // 需要等待readSource触发并通知我们套接字内部读缓冲区中的可用数据。
            
            [self resumeReadSource];
        }
        return;
    }
    
    if (flags & kStartingReadTLS)
    {
        LogVerbose(@"Waiting for SSL/TLS handshake to complete");
        
        // readQueue正在等待SSL/TLS握手完成。
        
        if (flags & kStartingWriteTLS)
        {
            if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
            {
                // 我们正在进行SSL握手。
                // 我们正在等待刚刚收到的数据。
                
                [self ssl_continueSSLHandshake];
            }
        }
        else
        {
            // 我们仍然在等待writeQueue耗尽并启动SSL/TLS进程。
            // 我们现在知道数据是可以读取的。
            
            if (![self usingCFStreamForTLS])
            {
                // 暂停读源，否则它将继续不间断地触发。
                
                [self suspendReadSource];
            }
        }
        
        return;
    }
    
    BOOL done        = NO;  // Completed read operation
    NSError *error   = nil; // Error occurred
    
    NSUInteger totalBytesReadForCurrentRead = 0;
    
    //
    // 步骤1 -从PREBUFFER读取
    //
    
    if ([preBuffer availableBytes] > 0)
    {
        // 有三种类型的读包:
        //
        // 1)读取所有可用数据。
        // 2)读取特定长度的数据。
        // 3)读到特定的终止符。
        
        NSUInteger bytesToCopy;
        
        if (currentRead->term != nil)
        {
            // 读类型#3 -读到终止符
            
            bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
        }
        else
        {
            // 阅读类型#1或#2
            
            bytesToCopy = [currentRead readLengthForNonTermWithHint:[preBuffer availableBytes]];
        }
        
        // 确保缓冲区中有足够的空间用于读取。
        
        [currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
        
        // 将字节从预缓冲区复制到包缓冲区
        
        uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset +
        currentRead->bytesDone;
        
        memcpy(buffer, [preBuffer readBuffer], bytesToCopy);
        
        // 从预缓冲区中删除复制的字节
        [preBuffer didRead:bytesToCopy];
        
        LogVerbose(@"copied(%lu) preBufferLength(%zu)", (unsigned long)bytesToCopy, [preBuffer availableBytes]);
        
        // 更新总数
        
        currentRead->bytesDone += bytesToCopy;
        totalBytesReadForCurrentRead += bytesToCopy;
        
        // 检查是否完成了读取操作
        
        if (currentRead->readLength > 0)
        {
            // 读取类型#2 -读取特定长度的数据
            
            done = (currentRead->bytesDone == currentRead->readLength);
        }
        else if (currentRead->term != nil)
        {
            // 读类型#3 -读到终止符
            
            // 我们的'done'变量是通过readLengthForTermWithPreBuffer:found:方法更新的
            
            if (!done && currentRead->maxLength > 0)
            {
                // 我们还没有完成，这里有一个集合maxLength。
                // 我们已经达到最大长度了吗?
                
                if (currentRead->bytesDone >= currentRead->maxLength)
                {
                    error = [self readMaxedOutError];
                }
            }
        }
        else
        {
            // 读取类型#1 -读取所有可用数据
            //
            // We're done as soon as
            // - 我们已经读取了所有可用的数据(在prebuffer和套接字中)
            // - 我们已经读取了读包的maxLength。
            
            done = ((currentRead->maxLength > 0) && (currentRead->bytesDone == currentRead->maxLength));
        }
        
    }
    
    //
    // 步骤2 -从套接字读取
    //
    
    BOOL socketEOF = (flags & kSocketHasReadEOF) ? YES : NO;  // 通过套接字(文件末尾)无需读取更多信息
    BOOL waiting   = !done && !error && !socketEOF && !hasBytesAvailable; // 数据用完了，等待更多
    
    if (!done && !error && !socketEOF && hasBytesAvailable)
    {
        NSAssert(([preBuffer availableBytes] == 0), @"Invalid logic");
        
        BOOL readIntoPreBuffer = NO;
        uint8_t *buffer = NULL;
        size_t bytesRead = 0;
        
        if (flags & kSocketSecure)
        {
            if ([self usingCFStreamForTLS])
            {
#if TARGET_OS_IPHONE
                
                // 对于TLS使用CFStream而不是SecureTransport
                
                NSUInteger defaultReadLength = (1024 * 32);
                
                NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
                                                                   shouldPreBuffer:&readIntoPreBuffer];
                
                // 确保缓冲区中有足够的空间用于读取。
                // 我们要么直接读入currentRead->缓冲区，要么读入临时预缓冲区。
                
                if (readIntoPreBuffer)
                {
                    [preBuffer ensureCapacityForWrite:bytesToRead];
                    
                    buffer = [preBuffer writeBuffer];
                }
                else
                {
                    [currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
                    
                    buffer = (uint8_t *)[currentRead->buffer mutableBytes]
                    + currentRead->startOffset
                    + currentRead->bytesDone;
                }
                
                // 将数据读入缓冲区
                
                CFIndex result = CFReadStreamRead(readStream, buffer, (CFIndex)bytesToRead);
                LogVerbose(@"CFReadStreamRead(): result = %i", (int)result);
                
                if (result < 0)
                {
                    error = (__bridge_transfer NSError *)CFReadStreamCopyError(readStream);
                }
                else if (result == 0)
                {
                    socketEOF = YES;
                }
                else
                {
                    waiting = YES;
                    bytesRead = (size_t)result;
                }
                
                // 我们只知道读取了多少解密字节。
                // 由于加密的开销，实际读取的字节数可能更多。
                // 因此我们重置了我们的标志，并依赖于下一个回调来提醒我们更多的数据。
                flags &= ~kSecureSocketHasBytesAvailable;
                
#endif
            }
            else
            {
                // 为TLS使用SecureTransport
                //
                // 我们知道:
                //  - 套接字上可用的字节数
                //  - sslPreBuffer中有多少加密字节
                //  - sslContext中有多少解码字节
                //
                // 但是我们不知道:
                //  - sslContext中有多少加密字节
                //
                // 所以我们通常用upper bound来代替。
                
                NSUInteger defaultReadLength = (1024 * 32);
                
                if (defaultReadLength < estimatedBytesAvailable) {
                    defaultReadLength = estimatedBytesAvailable + (1024 * 16);
                }
                
                NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
                                                                   shouldPreBuffer:&readIntoPreBuffer];
                
                if (bytesToRead > SIZE_MAX) { // NSUInteger可能大于size_t
                    bytesToRead = SIZE_MAX;
                }
                
                // 确保缓冲区中有足够的空间用于读取。
                //
                // 我们要么直接读入currentRead->缓冲区，要么读入临时预缓冲区。
                
                if (readIntoPreBuffer)
                {
                    [preBuffer ensureCapacityForWrite:bytesToRead];
                    
                    buffer = [preBuffer writeBuffer];
                }
                else
                {
                    [currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
                    
                    buffer = (uint8_t *)[currentRead->buffer mutableBytes]
                    + currentRead->startOffset
                    + currentRead->bytesDone;
                }
                
                // 苹果公司的文件表明:
                //  "读取操作可能返回errSSLWouldBlock，表明实际传输的数据比请求的少。"
                //
                // 然而，从10.7开始，函数有时会返回noErr，即使它没有读取足够多的数据。所以我们需要注意这一点。
                
                OSStatus result;
                do
                {
                    void *loop_buffer = buffer + bytesRead;
                    size_t loop_bytesToRead = (size_t)bytesToRead - bytesRead;
                    size_t loop_bytesRead = 0;
                    
                    result = SSLRead(sslContext, loop_buffer, loop_bytesToRead, &loop_bytesRead);
                    LogVerbose(@"read from secure socket = %u", (unsigned)loop_bytesRead);
                    
                    bytesRead += loop_bytesRead;
                    
                } while ((result == noErr) && (bytesRead < bytesToRead));
                
                
                if (result != noErr)
                {
                    if (result == errSSLWouldBlock)
                        waiting = YES;
                    else
                    {
                        if (result == errSSLClosedGraceful || result == errSSLClosedAbort)
                        {
                            // 我们已经到了stream的尽头。
                            // 处理这个问题的方法与从套接字中执行EOF的方法相同。
                            socketEOF = YES;
                            sslErrCode = result;
                        }
                        else
                        {
                            error = [self sslError:result];
                        }
                    }
                    // 当SSLRead函数能够读取一些数据时，可能会发生bytesRead>0的情况，即使结果是errSSLWouldBlock,
                    // 但不是我们请求的完整数量。
                    
                    if (bytesRead <= 0)
                    {
                        bytesRead = 0;
                    }
                }
                
                // 不要修改socketFDBytesAvailable。
                // 它将通过SSLReadFunction()更新。
            }
        }
        else
        {
            // 正常的套接字操作
            
            NSUInteger bytesToRead;
            
            // 有三种类型的读包:
            //
            // 1)读取所有可用数据。
            // 2)读取特定长度的数据。
            // 3)读到特定的终止符。
            
            if (currentRead->term != nil)
            {
                // Read type #3 - read up to a terminator
                
                bytesToRead = [currentRead readLengthForTermWithHint:estimatedBytesAvailable
                                                     shouldPreBuffer:&readIntoPreBuffer];
            }
            else
            {
                // Read type #1 or #2
                
                bytesToRead = [currentRead readLengthForNonTermWithHint:estimatedBytesAvailable];
            }
            
            if (bytesToRead > SIZE_MAX) { // NSUInteger may be bigger than size_t (read param 3)
                bytesToRead = SIZE_MAX;
            }
            
            //确保缓冲区中有足够的空间供我们阅读。
            //
            //我们要么直接读入currentRead->缓冲区，
            //或者我们正在读取临时预缓冲区。
            
            if (readIntoPreBuffer)
            {
                [preBuffer ensureCapacityForWrite:bytesToRead];
                
                buffer = [preBuffer writeBuffer];
            }
            else
            {
                [currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
                
                buffer = (uint8_t *)[currentRead->buffer mutableBytes]
                + currentRead->startOffset
                + currentRead->bytesDone;
            }
            
            // Read data into buffer
            
            int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
            
            ssize_t result = read(socketFD, buffer, (size_t)bytesToRead);
            LogVerbose(@"read from socket = %i", (int)result);
            
            if (result < 0)
            {
                if (errno == EWOULDBLOCK)
                    waiting = YES;
                else
                    error = [self errorWithErrno:errno reason:@"Error in read() function"];
                
                socketFDBytesAvailable = 0;
            }
            else if (result == 0)
            {
                socketEOF = YES;
                socketFDBytesAvailable = 0;
            }
            else
            {
                bytesRead = result;
                
                if (bytesRead < bytesToRead)
                {
                    // 读取返回的数据比请求的少。
                    // 这意味着socketFDBytesAvailable由于时间问题有点不正常
                    // 因为我们在readSource事件触发时从套接字读取。
                    socketFDBytesAvailable = 0;
                }
                else
                {
                    if (socketFDBytesAvailable <= bytesRead)
                        socketFDBytesAvailable = 0;
                    else
                        socketFDBytesAvailable -= bytesRead;
                }
                
                if (socketFDBytesAvailable == 0)
                {
                    waiting = YES;
                }
            }
        }
        
        if (bytesRead > 0)
        {
            // 检查是否完成了读取操作
            
            if (currentRead->readLength > 0)
            {
                // 读取类型#2 -读取特定长度的数据
                //
                // 注意:当我们读取特定长度的数据时，永远不应该使用预缓冲区。
                
                NSAssert(readIntoPreBuffer == NO, @"Invalid logic");
                
                currentRead->bytesDone += bytesRead;
                totalBytesReadForCurrentRead += bytesRead;
                
                done = (currentRead->bytesDone == currentRead->readLength);
            }
            else if (currentRead->term != nil)
            {
                // 读类型#3 -读到终止符
                
                if (readIntoPreBuffer)
                {
                    // 我们只是将一大块数据读入预缓冲区
                    
                    [preBuffer didWrite:bytesRead];
                    LogVerbose(@"read data into preBuffer - preBuffer.length = %zu", [preBuffer availableBytes]);
                    
                    // 搜索终止序列
                    
                    NSUInteger bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
                    LogVerbose(@"copying %lu bytes from preBuffer", (unsigned long)bytesToCopy);
                    
                    // 确保读包的缓冲区上有空间
                    
                    [currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
                    
                    // 将字节从预缓冲区复制到读缓冲区
                    
                    uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
                    + currentRead->bytesDone;
                    
                    memcpy(readBuf, [preBuffer readBuffer], bytesToCopy);
                    
                    // 从预缓冲区中删除复制的字节
                    [preBuffer didRead:bytesToCopy];
                    LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
                    
                    // 更新总数
                    currentRead->bytesDone += bytesToCopy;
                    totalBytesReadForCurrentRead += bytesToCopy;
                    
                    // 我们的“done”变量是通过上面的readLengthForTermWithPreBuffer:found:方法更新的
                }
                else
                {
                    // 我们只是把一大块数据直接读入数据包的缓冲区。
                    // 我们需要把溢出的部分移到预缓冲区。
                    
                    NSInteger overflow = [currentRead searchForTermAfterPreBuffering:bytesRead];
                    
                    if (overflow == 0)
                    {
                        // 完美的匹配!
                        // 我们读取的每个字节都保存在读取缓冲区中，
                        // 我们读的最后一个字节是这个终止符的最后一个字节。
                        
                        currentRead->bytesDone += bytesRead;
                        totalBytesReadForCurrentRead += bytesRead;
                        done = YES;
                    }
                    else if (overflow > 0)
                    {
                        // 这个词是在我们读到的数据中发现的，
                        // 还有一些额外的字节延伸到终止符结束之后。
                        // 我们需要把这些多余的字节从读包移到预缓冲区。
                        
                        NSInteger underflow = bytesRead - overflow;
                        
                        // 将多余的数据复制到预缓冲区
                        
                        LogVerbose(@"copying %ld overflow bytes into preBuffer", (long)overflow);
                        [preBuffer ensureCapacityForWrite:overflow];
                        
                        uint8_t *overflowBuffer = buffer + underflow;
                        memcpy([preBuffer writeBuffer], overflowBuffer, overflow);
                        
                        [preBuffer didWrite:overflow];
                        LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
                        
                        // 注意:completeCurrentRead方法将为我们修剪缓冲区。
                        
                        currentRead->bytesDone += underflow;
                        totalBytesReadForCurrentRead += underflow;
                        done = YES;
                    }
                    else
                    {
                        // 在我们读取的数据中没有找到该终止符。
                        
                        currentRead->bytesDone += bytesRead;
                        totalBytesReadForCurrentRead += bytesRead;
                        done = NO;
                    }
                }
                
                if (!done && currentRead->maxLength > 0)
                {
                    // 我们还没有完成，这里有设置maxLength。
                    // 我们已经达到最大长度了吗?
                    
                    if (currentRead->bytesDone >= currentRead->maxLength)
                    {
                        error = [self readMaxedOutError];
                    }
                }
            }
            else
            {
                // 读取类型#1 -读取所有可用数据
                
                if (readIntoPreBuffer)
                {
                    // 我们只是将数据块读入预缓冲区
                    
                    [preBuffer didWrite:bytesRead];
                    
                    // 现在将数据复制到读取包中。
                    //
                    // 回想一下，我们没有直接读入包的缓冲区以避免内存分配过多，因为我们不知道有多少数据可以读取。
                    //
                    // 确保读包的缓冲区上有空间
                    
                    [currentRead ensureCapacityForAdditionalDataOfLength:bytesRead];
                    
                    // 将字节从预缓冲区复制到读缓冲区
                    
                    uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
                    + currentRead->bytesDone;
                    
                    memcpy(readBuf, [preBuffer readBuffer], bytesRead);
                    
                    // 从预缓冲区中删除复制的字节
                    [preBuffer didRead:bytesRead];
                    
                    // 更新总数
                    currentRead->bytesDone += bytesRead;
                    totalBytesReadForCurrentRead += bytesRead;
                }
                else
                {
                    currentRead->bytesDone += bytesRead;
                    totalBytesReadForCurrentRead += bytesRead;
                }
                
                done = YES;
            }
            
        } // if (bytesRead > 0)
        
    } // if (!done && !error && !socketEOF && hasBytesAvailable)
    
    
    if (!done && currentRead->readLength == 0 && currentRead->term == nil)
    {
        // 读取类型#1 -读取所有可用数据
        //
        // 如果我们从预缓冲区而不是套接字读取数据，我们可能会到达这里。
        
        done = (totalBytesReadForCurrentRead > 0);
    }
    
    //看看我们是否完成了任务，或者是否取得了进展
    
    if (done)
    {
        [self completeCurrentRead];
        
        if (!error && (!socketEOF || [preBuffer availableBytes] > 0))
        {
            [self maybeDequeueRead];
        }
    }
    else if (totalBytesReadForCurrentRead > 0)
    {
        // 我们还没有读完类型#2或#3，但是我们已经读了一些字节
        //
        // 我们确保设置“等待”是为了恢复readSource(如果它被挂起)。
        // 如果当前读的长度足够大，则有可能到达此点而不设置“等待”。
        // 在这种情况下，我们可能已经成功地读取了一些upperbound，但是这个upperbound可能小于所需的长度。
        waiting = YES;
        
        __strong id theDelegate = delegate;
        
        if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadPartialDataOfLength:tag:)])
        {
            long theReadTag = currentRead->tag;
            
            dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
                [theDelegate socket:self didReadPartialDataOfLength:totalBytesReadForCurrentRead tag:theReadTag];
            }});
        }
    }
    
    // Check for errors
    
    if (error)
    {
        [self closeWithError:error];
    }
    else if (socketEOF)
    {
        [self doReadEOF];
    }
    else if (waiting)
    {
        if (![self usingCFStreamForTLS])
        {
            // 监控套接字的可读性(如果我们还没有这样做的话)
            [self resumeReadSource];
        }
    }
    
    // 如果没有在上面的错误案例中添加return语句，不要在这里添加任何代码。
}

- (void)doReadEOF
{
    LogTrace();
    
    // 此方法可以调用多次。
    // 如果在预缓冲区中仍然有数据时读取EOF，
    // 然后，可以在调用doReadData之后继续调用此方法，以查看是否应该断开连接。
    
    flags |= kSocketHasReadEOF;
    
    if (flags & kSocketSecure)
    {
        // 如果SSL层有任何缓冲数据，现在就将其刷新到preBuffer中。
        
        [self flushSSLBuffers];
    }
    
    BOOL shouldDisconnect = NO;
    NSError *error = nil;
    
    if ((flags & kStartingReadTLS) || (flags & kStartingWriteTLS))
    {
        // 我们在startTLS期间或之前收到了EOF。
        // SSL/TLS握手现在是不可能的，所以这是一种不可恢复的情况。
        
        shouldDisconnect = YES;
        
        if ([self usingSecureTransportForTLS])
        {
            error = [self sslError:errSSLClosedAbort];
        }
    }
    else if (flags & kReadStreamClosed)
    {
        // 预缓冲液已经被排干。
        // 该配置允许半双工连接。
        // 我们之前检查了套接字，它看起来是可写的。
        // 因此，我们将read流标记为closed并通知委托。
        //
        // 根据半双工合同，当写操作失败或手动关闭套接字时，套接字将被关闭
        
        shouldDisconnect = NO;
    }
    else if ([preBuffer availableBytes] > 0)
    {
        LogVerbose(@"Socket reached EOF, but there is still data available in prebuffer");
        
        // 虽然我们无法从套接字中读取更多的数据，
        // 但是已有的数据已经预先缓存，我们可以读取这些数据。
        shouldDisconnect = NO;
    }
    else if (config & kAllowHalfDuplexConnection)
    {
        // 我们刚刚从套接字的读取流中收到一个EOF(文件末尾)。
        // 这意味着套接字的远程端(我们所连接的对等端)已经明确声明不会向我们发送任何数据。
        //
        // 查询套接字，看看它是否仍然是可写的。(也许同伴会继续从我们这里读取数据)
        
        int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
        
        struct pollfd pfd[1];
        pfd[0].fd = socketFD;
        pfd[0].events = POLLOUT;
        pfd[0].revents = 0;
        
        poll(pfd, 1, 0);
        
        if (pfd[0].revents & POLLOUT)
        {
            // 套接字似乎仍然是可写的
            
            shouldDisconnect = NO;
            flags |= kReadStreamClosed;
            
            // 通知委托我们要进行半双工
            
            __strong id theDelegate = delegate;
            
            if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidCloseReadStream:)])
            {
                dispatch_async(delegateQueue, ^{ @autoreleasepool {
                    
                    [theDelegate socketDidCloseReadStream:self];
                }});
            }
        }
        else
        {
            shouldDisconnect = YES;
        }
    }
    else
    {
        shouldDisconnect = YES;
    }
    
    
    if (shouldDisconnect)
    {
        if (error == nil)
        {
            if ([self usingSecureTransportForTLS])
            {
                if (sslErrCode != noErr && sslErrCode != errSSLClosedGraceful)
                {
                    error = [self sslError:sslErrCode];
                }
                else
                {
                    error = [self connectionClosedError];
                }
            }
            else
            {
                error = [self connectionClosedError];
            }
        }
        [self closeWithError:error];
    }
    else
    {
        if (![self usingCFStreamForTLS])
        {
            // 暂停读取源(如果需要)
            
            [self suspendReadSource];
        }
    }
}

- (void)completeCurrentRead
{
    LogTrace();
    
    NSAssert(currentRead, @"Trying to complete current read when there is no current read.");
    
    
    NSData *result = nil;
    
    if (currentRead->bufferOwner)
    {
        // 我们代表用户创建了缓冲区。
        // 将缓冲区修剪到适当的大小。
        [currentRead->buffer setLength:currentRead->bytesDone];
        
        result = currentRead->buffer;
    }
    else
    {
        // 我们没有创建缓冲区。
        // 缓冲区由调用者拥有。
        // 只有当我们必须增加缓冲区的大小时才修剪它。
        
        if ([currentRead->buffer length] > currentRead->originalBufferLength)
        {
            NSUInteger readSize = currentRead->startOffset + currentRead->bytesDone;
            NSUInteger origSize = currentRead->originalBufferLength;
            
            NSUInteger buffSize = MAX(readSize, origSize);
            
            [currentRead->buffer setLength:buffSize];
        }
        
        uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset;
        
        result = [NSData dataWithBytesNoCopy:buffer length:currentRead->bytesDone freeWhenDone:NO];
    }
    
    __strong id theDelegate = delegate;
    
    if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadData:withTag:)])
    {
        INXAsyncReadPacket *theRead = currentRead; // Ensure currentRead retained since result may not own buffer
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            [theDelegate socket:self didReadData:result withTag:theRead->tag];
        }});
    }
    
    [self endCurrentRead];
}

- (void)endCurrentRead
{
    if (readTimer)
    {
        dispatch_source_cancel(readTimer);
        readTimer = NULL;
    }
#if __has_feature(objc_arc)
#else
    [currentRead release];
#endif
    currentRead = nil;
}

- (void)setupReadTimerWithTimeout:(NSTimeInterval)timeout
{
    if (timeout >= 0.0)
    {
        readTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
        
        __weak INXAsyncSocket *weakSelf = self;
        
        dispatch_source_set_event_handler(readTimer, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            __strong INXAsyncSocket *strongSelf = weakSelf;
            if (strongSelf == nil) return_from_block;
            
            [strongSelf doReadTimeout];
            
#pragma clang diagnostic pop
        }});
        
#if !OS_OBJECT_USE_OBJC
        dispatch_source_t theReadTimer = readTimer;
        dispatch_source_set_cancel_handler(readTimer, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            LogVerbose(@"dispatch_release(readTimer)");
            dispatch_release(theReadTimer);
            
#pragma clang diagnostic pop
        });
#endif
        
        dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
        
        dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(readTimer);
    }
}

- (void)doReadTimeout
{
    // 这有点棘手。
    // 理想情况下，我们希望同步地向委托查询超时扩展。
    // 但是如果同步执行，就有可能出现死锁。
    // 因此，我们必须异步地这样做，并从委托块中回调到我们自己。
    
    flags |= kReadsPaused;
    
    __strong id theDelegate = delegate;
    
    if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutReadWithTag:elapsed:bytesDone:)])
    {
        INXAsyncReadPacket *theRead = currentRead;
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            NSTimeInterval timeoutExtension = 0.0;
            
            timeoutExtension = [theDelegate socket:self shouldTimeoutReadWithTag:theRead->tag
                                           elapsed:theRead->timeout
                                         bytesDone:theRead->bytesDone];
            
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                [self doReadTimeoutWithExtension:timeoutExtension];
            }});
        }});
    }
    else
    {
        [self doReadTimeoutWithExtension:0.0];
    }
}

- (void)doReadTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
    if (currentRead)
    {
        if (timeoutExtension > 0.0)
        {
            currentRead->timeout += timeoutExtension;
            
            // 重新安排计时器
            dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
            dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
            
            // 暂停读取，然后继续
            flags &= ~kReadsPaused;
            [self doReadData];
        }
        else
        {
            LogVerbose(@"ReadTimeout");
            
            [self closeWithError:[self readTimeoutError]];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Writing
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
    if ([data length] == 0) return;
    
    INXAsyncWritePacket *packet = [[INXAsyncWritePacket alloc] initWithData:data timeout:timeout tag:tag];
    
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        LogTrace();
        
        if ((self->flags & kSocketStarted) && !(self->flags & kForbidReadsWrites))
        {
            [self->writeQueue addObject:packet];
            [self maybeDequeueWrite];
        }
    }});
    
    // 不要依赖正在运行的块来释放包，
    // 因为队列可能在没有完成块的情况下被释放。
}

- (float)progressOfWriteReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
    __block float result = 0.0F;
    
    dispatch_block_t block = ^{
        
        if (!self->currentWrite || ![self->currentWrite isKindOfClass:[INXAsyncWritePacket class]])
        {
            // We're not writing anything right now.
            
            if (tagPtr != NULL)   *tagPtr = 0;
            if (donePtr != NULL)  *donePtr = 0;
            if (totalPtr != NULL) *totalPtr = 0;
            
            result = NAN;
        }
        else
        {
            NSUInteger done = self->currentWrite->bytesDone;
            NSUInteger total = [self->currentWrite->buffer length];
            
            if (tagPtr != NULL)   *tagPtr = self->currentWrite->tag;
            if (donePtr != NULL)  *donePtr = done;
            if (totalPtr != NULL) *totalPtr = total;
            
            result = (float)done / (float)total;
        }
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
    
    return result;
}

/**
 * 有条件地开始新写入。
 *
 * 当:
 *  -用户请求写
 *  -写请求完成后(处理下一个请求)
 *  -在套接字打开后立即处理任何挂起的请求
 *
 * 此方法还处理自动断开后读/写完成。
 **/
- (void)maybeDequeueWrite
{
    LogTrace();
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    
    // 如果我们当前没有处理写，而我们有可用的写流
    if ((currentWrite == nil) && (flags & kConnected))
    {
        if ([writeQueue count] > 0)
        {
            // Dequeue the next object in the write queue
            currentWrite = [writeQueue objectAtIndex:0];
            [writeQueue removeObjectAtIndex:0];
            
            
            if ([currentWrite isKindOfClass:[INXAsyncSpecialPacket class]])
            {
                LogVerbose(@"Dequeued INXAsyncSpecialPacket");
                
                // 尝试启动TLS
                flags |= kStartingWriteTLS;
                
                // 除非设置了kStartingReadTLS和kStartingWriteTLS，否则此方法不会执行任何操作
                [self maybeStartTLS];
            }
            else
            {
                LogVerbose(@"Dequeued INXAsyncWritePacket");
                
                // 设置写计时器(如果需要)
                [self setupWriteTimerWithTimeout:currentWrite->timeout];
                
                // 如果可能，立即写数据
                [self doWriteData];
            }
        }
        else if (flags & kDisconnectAfterWrites)
        {
            if (flags & kDisconnectAfterReads)
            {
                if (([readQueue count] == 0) && (currentRead == nil))
                {
                    [self closeWithError:nil];
                }
            }
            else
            {
                [self closeWithError:nil];
            }
        }
    }
}

- (void)doWriteData
{
    LogTrace();
    
    // writeSource通过socketQueue调用此方法
    
    if ((currentWrite == nil) || (flags & kWritesPaused))
    {
        LogVerbose(@"No currentWrite or kWritesPaused");
        
        // 这个时候不能写
        
        if ([self usingCFStreamForTLS])
        {
            // CFWriteStream只在有可用数据时触发一次。
            // 在调用CFWriteStreamWrite之前，它不会再次触发。
        }
        else
        {
            // 如果writeSource正在启动，我们需要暂停它
            // 否则它将继续一遍又一遍地发射。
            
            if (flags & kSocketCanAcceptBytes)
            {
                [self suspendWriteSource];
            }
        }
        return;
    }
    
    if (!(flags & kSocketCanAcceptBytes))
    {
        LogVerbose(@"No space available to write...");
        
        // 没有写的空间。
        
        if (![self usingCFStreamForTLS])
        {
            // 需要等待writeSource触发，并通知我们套接字内部写缓冲区中的可用空间。
            
            [self resumeWriteSource];
        }
        return;
    }
    
    if (flags & kStartingWriteTLS)
    {
        LogVerbose(@"Waiting for SSL/TLS handshake to complete");
        
        // writeQueue正在等待SSL/TLS握手完成。
        
        if (flags & kStartingReadTLS)
        {
            if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
            {
                // 我们正在进行SSL握手。
                // 我们正在等待套接字的内部OS缓冲区中的可用空间来继续写入。
                
                [self ssl_continueSSLHandshake];
            }
        }
        else
        {
            // 我们仍然在等待readQueue耗尽并启动SSL/TLS进程。
            // 现在我们知道我们可以写入套接字。
            
            if (![self usingCFStreamForTLS])
            {
                // 暂停写源，否则它将继续不停止地触发。
                
                [self suspendWriteSource];
            }
        }
        
        return;
    }
    
    // 注意:如果currentWrite是INXAsyncSpecialPacket (startTLS包)，则不调用此方法。
    
    BOOL waiting = NO;
    NSError *error = nil;
    size_t bytesWritten = 0;
    
    if (flags & kSocketSecure)
    {
        if ([self usingCFStreamForTLS])
        {
#if TARGET_OS_IPHONE
            
            //
            // 在CFStream中写数据(TLS内部)
            //
            
            const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
            
            NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
            
            if (bytesToWrite > SIZE_MAX) // NSUInteger可能大于size_t(写入参数3)
            {
                bytesToWrite = SIZE_MAX;
            }
            
            CFIndex result = CFWriteStreamWrite(writeStream, buffer, (CFIndex)bytesToWrite);
            LogVerbose(@"CFWriteStreamWrite(%lu) = %li", (unsigned long)bytesToWrite, result);
            
            if (result < 0)
            {
                error = (__bridge_transfer NSError *)CFWriteStreamCopyError(writeStream);
            }
            else
            {
                bytesWritten = (size_t)result;
                
                // 在这种情况下，我们总是将wait设置为true。
                // CFStream可能将我们的基础套接字更改为非阻塞。
                // 因此，如果我们试图在没有回调的情况下编写，可能会阻塞队列。
                waiting = YES;
            }
            
#endif
        }
        else
        {
            // 我们将使用SSLWrite函数。
            //
            // OSStatus SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed)
            //
            // 参数:
            // context     - SSL会话上下文引用.
            // data        - 指向要写入的数据缓冲区的指针。
            // dataLength  - 要写入的数据量，以字节为单位。
            // processed   - 返回时，实际写入的数据的长度(以字节为单位)。
            //
            // 听起来很直白，但是有一些需要注意的地方。
            //
            // SSLWrite方法以一种不明显(而且相当烦人)的方式运行。
            // 根据文件:
            //
            //   因为可以将底层连接配置为以非阻塞的方式进行操作，所以写操作可能返回errSSLWouldBlock，
            //   表示实际传输的数据少于请求的数据。在这种情况下，您应该重复对SSLWrite的调用，直到返回其他结果。
            //
            // 这听起来很完美，但是当我们的SSLWriteFunction返回errSSLWouldBlock时，
            // 然后，SSLWrite方法返回(带有适当的errSSLWouldBlock返回值)，
            // 但它设置处理为dataLength !!
            //
            // 换句话说，如果SSLWrite函数没有完全写出我们告诉它的所有数据，
            // 它没有告诉我们实际写了多少字节。
            // 例如，如果我们告诉它写256个字节，那么它实际上可能写128个字节，但是报告写了0个字节。
            //
            // 你可能会想:
            // 如果SSLWrite函数没有告诉我们写了多少字节，
            // 那么，下一次调用SSLWrite时，究竟应该如何更新参数(buffer & bytesToWrite)呢?
            //
            // 答案是SSLWrite缓存了我们让它写的所有数据，下次我们调用SSLWrite时，它会将这些数据推出。
            // 如果我们使用新数据调用SSLWrite，它将首先推出缓存的数据，然后是新数据。
            // 如果我们使用空数据调用SSLWrite，那么它将简单地推出缓存的数据。
            //
            // 为此，我们将把大的写分成一系列小的写
            // 这允许我们向委托报告进度。
            
            OSStatus result;
            
            BOOL hasCachedDataToWrite = (sslWriteCachedLength > 0);
            BOOL hasNewDataToWrite = YES;
            
            if (hasCachedDataToWrite)
            {
                size_t processed = 0;
                
                result = SSLWrite(sslContext, NULL, 0, &processed);
                
                if (result == noErr)
                {
                    bytesWritten = sslWriteCachedLength;
                    sslWriteCachedLength = 0;
                    
                    if ([currentWrite->buffer length] == (currentWrite->bytesDone + bytesWritten))
                    {
                        // 我们已经为当前写入写入了所有数据。
                        hasNewDataToWrite = NO;
                    }
                }
                else
                {
                    if (result == errSSLWouldBlock)
                    {
                        waiting = YES;
                    }
                    else
                    {
                        error = [self sslError:result];
                    }
                    
                    // 无法写入任何新数据，因为我们无法写入缓存的数据。
                    hasNewDataToWrite = NO;
                }
            }
            
            if (hasNewDataToWrite)
            {
                const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes]
                + currentWrite->bytesDone
                + bytesWritten;
                
                NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone - bytesWritten;
                
                if (bytesToWrite > SIZE_MAX) // NSUInteger可能大于size_t(写入参数3)
                {
                    bytesToWrite = SIZE_MAX;
                }
                
                size_t bytesRemaining = bytesToWrite;
                
                BOOL keepLooping = YES;
                while (keepLooping)
                {
                    const size_t sslMaxBytesToWrite = 32768;
                    size_t sslBytesToWrite = MIN(bytesRemaining, sslMaxBytesToWrite);
                    size_t sslBytesWritten = 0;
                    
                    result = SSLWrite(sslContext, buffer, sslBytesToWrite, &sslBytesWritten);
                    
                    if (result == noErr)
                    {
                        buffer += sslBytesWritten;
                        bytesWritten += sslBytesWritten;
                        bytesRemaining -= sslBytesWritten;
                        
                        keepLooping = (bytesRemaining > 0);
                    }
                    else
                    {
                        if (result == errSSLWouldBlock)
                        {
                            waiting = YES;
                            sslWriteCachedLength = sslBytesToWrite;
                        }
                        else
                        {
                            error = [self sslError:result];
                        }
                        
                        keepLooping = NO;
                    }
                    
                } // while (keepLooping)
                
            } // if (hasNewDataToWrite)
        }
    }
    else
    {
        //
        // 直接在原始套接字上写入数据
        //
        
        int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
        
        const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
        
        NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
        
        if (bytesToWrite > SIZE_MAX) // NSUInteger可以大于size_t(写入参数3)
        {
            bytesToWrite = SIZE_MAX;
        }
        
        ssize_t result = write(socketFD, buffer, (size_t)bytesToWrite);
        LogVerbose(@"wrote to socket = %zd", result);
        
        // Check results
        if (result < 0)
        {
            if (errno == EWOULDBLOCK)
            {
                waiting = YES;
            }
            else
            {
                error = [self errorWithErrno:errno reason:@"Error in write() function"];
            }
        }
        else
        {
            bytesWritten = result;
        }
    }
    
    // 我们写完了。
    // 如果我们明确地遇到socket告诉我们缓冲区没有空间的情况，
    // 然后我们立即恢复监听通知。
    //
    // 我们必须在删除另一个写入之前这样做，
    // 因为这可能会再次调用这个方法。
    //
    // 注意，如果涉及到CFStream，它可能恶意地将套接字置于阻塞模式。
    
    if (waiting)
    {
        flags &= ~kSocketCanAcceptBytes;
        
        if (![self usingCFStreamForTLS])
        {
            [self resumeWriteSource];
        }
    }
    
    // Check our results
    
    BOOL done = NO;
    
    if (bytesWritten > 0)
    {
        // Update total amount read for the current write
        currentWrite->bytesDone += bytesWritten;
        LogVerbose(@"currentWrite->bytesDone = %lu", (unsigned long)currentWrite->bytesDone);
        
        // Is packet done?
        done = (currentWrite->bytesDone == [currentWrite->buffer length]);
    }
    
    if (done)
    {
        [self completeCurrentWrite];
        
        if (!error)
        {
            dispatch_async(socketQueue, ^{ @autoreleasepool{
                
                [self maybeDequeueWrite];
            }});
        }
    }
    else
    {
        //我们写不完数据，
        //因此，我们正在等待另一个回调来通知我们lower-level输出缓冲区中的可用空间。
        
        if (!waiting && !error)
        {
            // 如果我们的写入能够接受一些数据，但不是所有数据，就会出现这种情况。
            
            flags &= ~kSocketCanAcceptBytes;
            
            if (![self usingCFStreamForTLS])
            {
                [self resumeWriteSource];
            }
        }
        
        if (bytesWritten > 0)
        {
            // 我们还没有写完，但是我们已经写了一些字节
            
            __strong id theDelegate = delegate;
            
            if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWritePartialDataOfLength:tag:)])
            {
                long theWriteTag = currentWrite->tag;
                
                dispatch_async(delegateQueue, ^{ @autoreleasepool {
                    
                    [theDelegate socket:self didWritePartialDataOfLength:bytesWritten tag:theWriteTag];
                }});
            }
        }
    }
    
    // Check for errors
    
    if (error)
    {
        [self closeWithError:[self errorWithErrno:errno reason:@"Error in write() function"]];
    }
    
    // 如果没有在上面的错误情况中添加return语句，不要在这里添加任何代码。
}

- (void)completeCurrentWrite
{
    LogTrace();
    
    NSAssert(currentWrite, @"Trying to complete current write when there is no current write.");
    
    
    __strong id theDelegate = delegate;
    
    if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWriteDataWithTag:)])
    {
        long theWriteTag = currentWrite->tag;
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            [theDelegate socket:self didWriteDataWithTag:theWriteTag];
        }});
    }
    
    [self endCurrentWrite];
}

- (void)endCurrentWrite
{
    if (writeTimer)
    {
        dispatch_source_cancel(writeTimer);
        writeTimer = NULL;
    }
#if __has_feature(objc_arc)
#else
    [currentWrite release];
#endif
    currentWrite = nil;
}

- (void)setupWriteTimerWithTimeout:(NSTimeInterval)timeout
{
    if (timeout >= 0.0)
    {
        writeTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
        
        __weak INXAsyncSocket *weakSelf = self;
        
        dispatch_source_set_event_handler(writeTimer, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            __strong INXAsyncSocket *strongSelf = weakSelf;
            if (strongSelf == nil) return_from_block;
            
            [strongSelf doWriteTimeout];
            
#pragma clang diagnostic pop
        }});
        
#if !OS_OBJECT_USE_OBJC
        dispatch_source_t theWriteTimer = writeTimer;
        dispatch_source_set_cancel_handler(writeTimer, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            LogVerbose(@"dispatch_release(writeTimer)");
            dispatch_release(theWriteTimer);
            
#pragma clang diagnostic pop
        });
#endif
        
        dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
        
        dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(writeTimer);
    }
}

- (void)doWriteTimeout
{
    // 这有点棘手。
    // 理想情况下，我们希望同步地向委托查询超时扩展。
    // 但是如果同步执行，就有可能出现死锁。
    // 因此，我们必须异步地这样做，并从委托块中回调到我们自己。
    
    flags |= kWritesPaused;
    
    __strong id theDelegate = delegate;
    
    if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutWriteWithTag:elapsed:bytesDone:)])
    {
        INXAsyncWritePacket *theWrite = currentWrite;
        
        dispatch_async(delegateQueue, ^{ @autoreleasepool {
            
            NSTimeInterval timeoutExtension = 0.0;
            
            timeoutExtension = [theDelegate socket:self shouldTimeoutWriteWithTag:theWrite->tag
                                           elapsed:theWrite->timeout
                                         bytesDone:theWrite->bytesDone];
            
            dispatch_async(self->socketQueue, ^{ @autoreleasepool {
                
                [self doWriteTimeoutWithExtension:timeoutExtension];
            }});
        }});
    }
    else
    {
        [self doWriteTimeoutWithExtension:0.0];
    }
}

- (void)doWriteTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
    if (currentWrite)
    {
        if (timeoutExtension > 0.0)
        {
            currentWrite->timeout += timeoutExtension;
            
            // 重新安排计时器
            dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
            dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
            
            // 停止写入，然后继续
            flags &= ~kWritesPaused;
            [self doWriteData];
        }
        else
        {
            LogVerbose(@"WriteTimeout");
            
            [self closeWithError:[self writeTimeoutError]];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)startTLS:(NSDictionary *)tlsSettings
{
    LogTrace();
    
    if (tlsSettings == nil)
    {
        // 将nil/NULL传递给CFReadStreamSetProperty与传递空字典的工作原理相同，
        // 但是，如果我们稍后试图获取远程主机的证书，则会导致问题。
        //
        // 确切地说，它导致以下返回NULL而不是正常的结果:
        // CFReadStreamCopyProperty(readStream, kCFStreamPropertySSLPeerCertificates)
        //
        // 所以我们用一个空字典来代替，这很好。
        
        tlsSettings = [NSDictionary dictionary];
    }
    
    INXAsyncSpecialPacket *packet = [[INXAsyncSpecialPacket alloc] initWithTLSSettings:tlsSettings];
    
    dispatch_async(socketQueue, ^{ @autoreleasepool {
        
        if ((self->flags & kSocketStarted) && !(self->flags & kQueuedTLS) && !(self->flags & kForbidReadsWrites))
        {
            [self->readQueue addObject:packet];
            [self->writeQueue addObject:packet];
            
            self->flags |= kQueuedTLS;
            
            [self maybeDequeueRead];
            [self maybeDequeueWrite];
        }
    }});
    
}

- (void)maybeStartTLS
{
    // 我们不能开始TLS，直到:
    // -在用户调用startTLS之前的所有队列读取都已完成
    // -在用户调用startTLS之前的所有排队写操作都已完成
    //
    // 当设置kStartingReadTLS和kStartingWriteTLS时，我们将知道这些条件都满足了
    
    if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
    {
        BOOL useSecureTransport = YES;
        
#if TARGET_OS_IPHONE
        {
            INXAsyncSpecialPacket *tlsPacket = (INXAsyncSpecialPacket *)currentRead;
            NSDictionary *tlsSettings = @{};
            if (tlsPacket) {
                tlsSettings = tlsPacket->tlsSettings;
            }
            NSNumber *value = [tlsSettings objectForKey:INXAsyncSocketUseCFStreamForTLS];
            if (value && [value boolValue])
                useSecureTransport = NO;
        }
#endif
        
        if (useSecureTransport)
        {
            [self ssl_startTLS];
        }
        else
        {
#if TARGET_OS_IPHONE
            [self cf_startTLS];
#endif
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via SecureTransport
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (OSStatus)sslReadWithBuffer:(void *)buffer length:(size_t *)bufferLength
{
    LogVerbose(@"sslReadWithBuffer:%p length:%lu", buffer, (unsigned long)*bufferLength);
    
    if ((socketFDBytesAvailable == 0) && ([sslPreBuffer availableBytes] == 0))
    {
        LogVerbose(@"%@ - No data available to read...", THIS_METHOD);
        
        // 无法读取数据。
        //
        // 需要等待readSource触发并通知我们套接字内部读缓冲区中的可用数据。
        
        [self resumeReadSource];
        
        *bufferLength = 0;
        return errSSLWouldBlock;
    }
    
    size_t totalBytesRead = 0;
    size_t totalBytesLeftToBeRead = *bufferLength;
    
    BOOL done = NO;
    BOOL socketError = NO;
    
    //
    //步骤1:从SSL预缓冲区读取
    //
    
    size_t sslPreBufferLength = [sslPreBuffer availableBytes];
    
    if (sslPreBufferLength > 0)
    {
        LogVerbose(@"%@: Reading from SSL pre buffer...", THIS_METHOD);
        
        size_t bytesToCopy;
        if (sslPreBufferLength > totalBytesLeftToBeRead)
            bytesToCopy = totalBytesLeftToBeRead;
        else
            bytesToCopy = sslPreBufferLength;
        
        LogVerbose(@"%@: Copying %zu bytes from sslPreBuffer", THIS_METHOD, bytesToCopy);
        
        memcpy(buffer, [sslPreBuffer readBuffer], bytesToCopy);
        [sslPreBuffer didRead:bytesToCopy];
        
        LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
        
        totalBytesRead += bytesToCopy;
        totalBytesLeftToBeRead -= bytesToCopy;
        
        done = (totalBytesLeftToBeRead == 0);
        
        if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
    }
    
    //
    // 步骤2:从套接字读取
    //
    
    if (!done && (socketFDBytesAvailable > 0))
    {
        LogVerbose(@"%@: Reading from socket...", THIS_METHOD);
        
        int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
        
        BOOL readIntoPreBuffer;
        size_t bytesToRead;
        uint8_t *buf;
        
        if (socketFDBytesAvailable > totalBytesLeftToBeRead)
        {
            // 将所有可用数据从套接字读入sslPreBuffer。
            // 然后将请求的数量复制到dataBuffer。
            
            LogVerbose(@"%@: Reading into sslPreBuffer...", THIS_METHOD);
            
            [sslPreBuffer ensureCapacityForWrite:socketFDBytesAvailable];
            
            readIntoPreBuffer = YES;
            bytesToRead = (size_t)socketFDBytesAvailable;
            buf = [sslPreBuffer writeBuffer];
        }
        else
        {
            // 将可用数据从套接字直接读入dataBuffer。
            
            LogVerbose(@"%@: Reading directly into dataBuffer...", THIS_METHOD);
            
            readIntoPreBuffer = NO;
            bytesToRead = totalBytesLeftToBeRead;
            buf = (uint8_t *)buffer + totalBytesRead;
        }
        
        ssize_t result = read(socketFD, buf, bytesToRead);
        LogVerbose(@"%@: read from socket = %zd", THIS_METHOD, result);
        
        if (result < 0)
        {
            LogVerbose(@"%@: read errno = %i", THIS_METHOD, errno);
            
            if (errno != EWOULDBLOCK)
            {
                socketError = YES;
            }
            
            socketFDBytesAvailable = 0;
        }
        else if (result == 0)
        {
            LogVerbose(@"%@: read EOF", THIS_METHOD);
            
            socketError = YES;
            socketFDBytesAvailable = 0;
        }
        else
        {
            size_t bytesReadFromSocket = result;
            
            if (socketFDBytesAvailable > bytesReadFromSocket)
                socketFDBytesAvailable -= bytesReadFromSocket;
            else
                socketFDBytesAvailable = 0;
            
            if (readIntoPreBuffer)
            {
                [sslPreBuffer didWrite:bytesReadFromSocket];
                
                size_t bytesToCopy = MIN(totalBytesLeftToBeRead, bytesReadFromSocket);
                
                LogVerbose(@"%@: Copying %zu bytes out of sslPreBuffer", THIS_METHOD, bytesToCopy);
                
                memcpy((uint8_t *)buffer + totalBytesRead, [sslPreBuffer readBuffer], bytesToCopy);
                [sslPreBuffer didRead:bytesToCopy];
                
                totalBytesRead += bytesToCopy;
                totalBytesLeftToBeRead -= bytesToCopy;
                
                LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
            }
            else
            {
                totalBytesRead += bytesReadFromSocket;
                totalBytesLeftToBeRead -= bytesReadFromSocket;
            }
            
            done = (totalBytesLeftToBeRead == 0);
            
            if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
        }
    }
    
    *bufferLength = totalBytesRead;
    
    if (done)
        return noErr;
    
    if (socketError)
        return errSSLClosedAbort;
    
    return errSSLWouldBlock;
}

- (OSStatus)sslWriteWithBuffer:(const void *)buffer length:(size_t *)bufferLength
{
    if (!(flags & kSocketCanAcceptBytes))
    {
        // 不能写。
        //
        // Need to wait for writeSource to fire and notify us of
        // 需要等待writeSource触发并通知我们套接字内部写缓冲区中的可用空间。
        
        [self resumeWriteSource];
        
        *bufferLength = 0;
        return errSSLWouldBlock;
    }
    
    size_t bytesToWrite = *bufferLength;
    size_t bytesWritten = 0;
    
    BOOL done = NO;
    BOOL socketError = NO;
    
    int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
    
    ssize_t result = write(socketFD, buffer, bytesToWrite);
    
    if (result < 0)
    {
        if (errno != EWOULDBLOCK)
        {
            socketError = YES;
        }
        
        flags &= ~kSocketCanAcceptBytes;
    }
    else if (result == 0)
    {
        flags &= ~kSocketCanAcceptBytes;
    }
    else
    {
        bytesWritten = result;
        
        done = (bytesWritten == bytesToWrite);
    }
    
    *bufferLength = bytesWritten;
    
    if (done)
        return noErr;
    
    if (socketError)
        return errSSLClosedAbort;
    
    return errSSLWouldBlock;
}

static OSStatus SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    INXAsyncSocket *asyncSocket = (__bridge INXAsyncSocket *)connection;
    
    NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
    
    return [asyncSocket sslReadWithBuffer:data length:dataLength];
}

static OSStatus SSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    INXAsyncSocket *asyncSocket = (__bridge INXAsyncSocket *)connection;
    
    NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
    
    return [asyncSocket sslWriteWithBuffer:data length:dataLength];
}

- (void)ssl_startTLS
{
    LogTrace();
    
    LogVerbose(@"Starting TLS (via SecureTransport)...");
    
    OSStatus status;
    
    INXAsyncSpecialPacket *tlsPacket = (INXAsyncSpecialPacket *)currentRead;
    if (tlsPacket == nil) // Code to quiet the analyzer
    {
        NSAssert(NO, @"Logic error");
        
        [self closeWithError:[self otherError:@"Logic error"]];
        return;
    }
    NSDictionary *tlsSettings = tlsPacket->tlsSettings;
    
    // Create SSLContext, and setup IO callbacks and connection ref
    
    BOOL isServer = [[tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLIsServer] boolValue];
    
#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
    {
        if (isServer)
            sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
        else
            sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
        
        if (sslContext == NULL)
        {
            [self closeWithError:[self otherError:@"Error in SSLCreateContext"]];
            return;
        }
    }
#else // (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
    {
        status = SSLNewContext(isServer, &sslContext);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLNewContext"]];
            return;
        }
    }
#endif
    
    status = SSLSetIOFuncs(sslContext, &SSLReadFunction, &SSLWriteFunction);
    if (status != noErr)
    {
        [self closeWithError:[self otherError:@"Error in SSLSetIOFuncs"]];
        return;
    }
    
    status = SSLSetConnection(sslContext, (__bridge SSLConnectionRef)self);
    if (status != noErr)
    {
        [self closeWithError:[self otherError:@"Error in SSLSetConnection"]];
        return;
    }
    
    
    BOOL shouldManuallyEvaluateTrust = [[tlsSettings objectForKey:INXAsyncSocketManuallyEvaluateTrust] boolValue];
    if (shouldManuallyEvaluateTrust)
    {
        if (isServer)
        {
            [self closeWithError:[self otherError:@"Manual trust validation is not supported for server sockets"]];
            return;
        }
        
        status = SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetSessionOption"]];
            return;
        }
        
#if !TARGET_OS_IPHONE && (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
        
        // 来自苹果文档的说明:
        //
        // 在OS X 10.8之前，只需要在Mac上调用SSLSetEnableCertVerify。
        // 在OS X 10.8和以后的版本设置kSSLSessionOptionBreakOnServerAuth总是禁用内置的信任评估
        // 所有版本的iOS都表现得像OS X 10.8，因此SSLSetEnableCertVerify在该平台上根本不可用。
        
        status = SSLSetEnableCertVerify(sslContext, NO);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetEnableCertVerify"]];
            return;
        }
        
#endif
    }
    
    // 根据给定的设置配置SSLContext
    //
    // Checklist:
    //  1. kCFStreamSSLPeerName
    //  2. kCFStreamSSLCertificates
    //  3. INXAsyncSocketSSLPeerID
    //  4. INXAsyncSocketSSLProtocolVersionMin
    //  5. INXAsyncSocketSSLProtocolVersionMax
    //  6. INXAsyncSocketSSLSessionOptionFalseStart
    //  7. INXAsyncSocketSSLSessionOptionSendOneByteRecord
    //  8. INXAsyncSocketSSLCipherSuites
    //  9. INXAsyncSocketSSLDiffieHellmanParameters (Mac)
    //
    // Deprecated (throw error):
    // 10. kCFStreamSSLAllowsAnyRoot
    // 11. kCFStreamSSLAllowsExpiredRoots
    // 12. kCFStreamSSLAllowsExpiredCertificates
    // 13. kCFStreamSSLValidatesCertificateChain
    // 14. kCFStreamSSLLevel
    
    id value;
    
    // 1. kCFStreamSSLPeerName
    
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLPeerName];
    if ([value isKindOfClass:[NSString class]])
    {
        NSString *peerName = (NSString *)value;
        
        const char *peer = [peerName UTF8String];
        size_t peerLen = strlen(peer);
        
        status = SSLSetPeerDomainName(sslContext, peer, peerLen);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetPeerDomainName"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for kCFStreamSSLPeerName. Value must be of type NSString.");
        
        [self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLPeerName."]];
        return;
    }
    
    // 2. kCFStreamSSLCertificates
    
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLCertificates];
    if ([value isKindOfClass:[NSArray class]])
    {
        CFArrayRef certs = (__bridge CFArrayRef)value;
        
        status = SSLSetCertificate(sslContext, certs);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetCertificate"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for kCFStreamSSLCertificates. Value must be of type NSArray.");
        
        [self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLCertificates."]];
        return;
    }
    
    // 3. INXAsyncSocketSSLPeerID
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLPeerID];
    if ([value isKindOfClass:[NSData class]])
    {
        NSData *peerIdData = (NSData *)value;
        
        status = SSLSetPeerID(sslContext, [peerIdData bytes], [peerIdData length]);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetPeerID"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLPeerID. Value must be of type NSData."
                 @" (You can convert strings to data using a method like"
                 @" [string dataUsingEncoding:NSUTF8StringEncoding])");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLPeerID."]];
        return;
    }
    
    // 4. INXAsyncSocketSSLProtocolVersionMin
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLProtocolVersionMin];
    if ([value isKindOfClass:[NSNumber class]])
    {
        SSLProtocol minProtocol = (SSLProtocol)[(NSNumber *)value intValue];
        if (minProtocol != kSSLProtocolUnknown)
        {
            status = SSLSetProtocolVersionMin(sslContext, minProtocol);
            if (status != noErr)
            {
                [self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMin"]];
                return;
            }
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLProtocolVersionMin. Value must be of type NSNumber.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLProtocolVersionMin."]];
        return;
    }
    
    // 5. INXAsyncSocketSSLProtocolVersionMax
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLProtocolVersionMax];
    if ([value isKindOfClass:[NSNumber class]])
    {
        SSLProtocol maxProtocol = (SSLProtocol)[(NSNumber *)value intValue];
        if (maxProtocol != kSSLProtocolUnknown)
        {
            status = SSLSetProtocolVersionMax(sslContext, maxProtocol);
            if (status != noErr)
            {
                [self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMax"]];
                return;
            }
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLProtocolVersionMax. Value must be of type NSNumber.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLProtocolVersionMax."]];
        return;
    }
    
    // 6. INXAsyncSocketSSLSessionOptionFalseStart
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLSessionOptionFalseStart];
    if ([value isKindOfClass:[NSNumber class]])
    {
        status = SSLSetSessionOption(sslContext, kSSLSessionOptionFalseStart, [value boolValue]);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionFalseStart)"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLSessionOptionFalseStart. Value must be of type NSNumber.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLSessionOptionFalseStart."]];
        return;
    }
    
    // 7. INXAsyncSocketSSLSessionOptionSendOneByteRecord
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLSessionOptionSendOneByteRecord];
    if ([value isKindOfClass:[NSNumber class]])
    {
        status = SSLSetSessionOption(sslContext, kSSLSessionOptionSendOneByteRecord, [value boolValue]);
        if (status != noErr)
        {
            [self closeWithError:
             [self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionSendOneByteRecord)"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLSessionOptionSendOneByteRecord."
                 @" Value must be of type NSNumber.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLSessionOptionSendOneByteRecord."]];
        return;
    }
    
    // 8. INXAsyncSocketSSLCipherSuites
    
    value = [tlsSettings objectForKey:INXAsyncSocketSSLCipherSuites];
    if ([value isKindOfClass:[NSArray class]])
    {
        NSArray *cipherSuites = (NSArray *)value;
        NSUInteger numberCiphers = [cipherSuites count];
        SSLCipherSuite ciphers[numberCiphers];
        
        NSUInteger cipherIndex;
        for (cipherIndex = 0; cipherIndex < numberCiphers; cipherIndex++)
        {
            NSNumber *cipherObject = [cipherSuites objectAtIndex:cipherIndex];
            ciphers[cipherIndex] = [cipherObject shortValue];
        }
        
        status = SSLSetEnabledCiphers(sslContext, ciphers, numberCiphers);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetEnabledCiphers"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLCipherSuites. Value must be of type NSArray.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLCipherSuites."]];
        return;
    }
    
    // 9. INXAsyncSocketSSLDiffieHellmanParameters
    
#if !TARGET_OS_IPHONE
    value = [tlsSettings objectForKey:INXAsyncSocketSSLDiffieHellmanParameters];
    if ([value isKindOfClass:[NSData class]])
    {
        NSData *diffieHellmanData = (NSData *)value;
        
        status = SSLSetDiffieHellmanParams(sslContext, [diffieHellmanData bytes], [diffieHellmanData length]);
        if (status != noErr)
        {
            [self closeWithError:[self otherError:@"Error in SSLSetDiffieHellmanParams"]];
            return;
        }
    }
    else if (value)
    {
        NSAssert(NO, @"Invalid value for INXAsyncSocketSSLDiffieHellmanParameters. Value must be of type NSData.");
        
        [self closeWithError:[self otherError:@"Invalid value for INXAsyncSocketSSLDiffieHellmanParameters."]];
        return;
    }
#endif
    
    // DEPRECATED checks
    
    // 10. kCFStreamSSLAllowsAnyRoot
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsAnyRoot];
#pragma clang diagnostic pop
    if (value)
    {
        NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsAnyRoot"
                 @" - You must use manual trust evaluation");
        
        [self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsAnyRoot"]];
        return;
    }
    
    // 11. kCFStreamSSLAllowsExpiredRoots
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredRoots];
#pragma clang diagnostic pop
    if (value)
    {
        NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"
                 @" - You must use manual trust evaluation");
        
        [self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"]];
        return;
    }
    
    // 12. kCFStreamSSLValidatesCertificateChain
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLValidatesCertificateChain];
#pragma clang diagnostic pop
    if (value)
    {
        NSAssert(NO, @"Security option unavailable - kCFStreamSSLValidatesCertificateChain"
                 @" - You must use manual trust evaluation");
        
        [self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLValidatesCertificateChain"]];
        return;
    }
    
    // 13. kCFStreamSSLAllowsExpiredCertificates
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredCertificates];
#pragma clang diagnostic pop
    if (value)
    {
        NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"
                 @" - You must use manual trust evaluation");
        
        [self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"]];
        return;
    }
    
    // 14. kCFStreamSSLLevel
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLLevel];
#pragma clang diagnostic pop
    if (value)
    {
        NSAssert(NO, @"Security option unavailable - kCFStreamSSLLevel"
                 @" - You must use INXAsyncSocketSSLProtocolVersionMin & INXAsyncSocketSSLProtocolVersionMax");
        
        [self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLLevel"]];
        return;
    }
    
    // 设置sslPreBuffer
    //
    // preBuffer中的任何数据都需要移动到sslPreBuffer中，
    // 因为这些数据现在是安全读取流的一部分。
    
    sslPreBuffer = [[INXAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
    
    size_t preBufferLength  = [preBuffer availableBytes];
    
    if (preBufferLength > 0)
    {
        [sslPreBuffer ensureCapacityForWrite:preBufferLength];
        
        memcpy([sslPreBuffer writeBuffer], [preBuffer readBuffer], preBufferLength);
        [preBuffer didRead:preBufferLength];
        [sslPreBuffer didWrite:preBufferLength];
    }
    
    sslErrCode = lastSSLHandshakeError = noErr;
    
    // 启动SSL握手过程
    
    [self ssl_continueSSLHandshake];
}

- (void)ssl_continueSSLHandshake
{
    LogTrace();
    
    // 如果返回值为noErr，则会话已准备好进行正常的安全通信。
    // 如果返回值为errSSLWouldBlock，则必须再次调用SSLHandshake函数。
    // 如果返回值为errSSLServerAuthCompleted，我们询问委托是否应该信任服务器，
    // 然后再次调用SSLHandshake恢复握手或关闭连接“errSSLPeerBadCert”SSL错误。
    // 否则，返回值指示错误代码。
    
    OSStatus status = SSLHandshake(sslContext);
    lastSSLHandshakeError = status;
    
    if (status == noErr)
    {
        LogVerbose(@"SSLHandshake complete");
        
        flags &= ~kStartingReadTLS;
        flags &= ~kStartingWriteTLS;
        
        flags |=  kSocketSecure;
        
        __strong id theDelegate = delegate;
        
        if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
        {
            dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
                [theDelegate socketDidSecure:self];
            }});
        }
        
        [self endCurrentRead];
        [self endCurrentWrite];
        
        [self maybeDequeueRead];
        [self maybeDequeueWrite];
    }
    else if (status == errSSLPeerAuthCompleted)
    {
        LogVerbose(@"SSLHandshake peerAuthCompleted - awaiting delegate approval");
        
        __block SecTrustRef trust = NULL;
        status = SSLCopyPeerTrust(sslContext, &trust);
        if (status != noErr)
        {
            [self closeWithError:[self sslError:status]];
            return;
        }
        
        int aStateIndex = stateIndex;
        dispatch_queue_t theSocketQueue = socketQueue;
        
        __weak INXAsyncSocket *weakSelf = self;
        
        void (^comletionHandler)(BOOL) = ^(BOOL shouldTrust){ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
            
            dispatch_async(theSocketQueue, ^{ @autoreleasepool {
                
                if (trust) {
                    CFRelease(trust);
                    trust = NULL;
                }
                
                __strong INXAsyncSocket *strongSelf = weakSelf;
                if (strongSelf)
                {
                    [strongSelf ssl_shouldTrustPeer:shouldTrust stateIndex:aStateIndex];
                }
            }});
            
#pragma clang diagnostic pop
        }};
        
        __strong id theDelegate = delegate;
        
        if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReceiveTrust:completionHandler:)])
        {
            dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
                [theDelegate socket:self didReceiveTrust:trust completionHandler:comletionHandler];
            }});
        }
        else
        {
            if (trust) {
                CFRelease(trust);
                trust = NULL;
            }
            
            NSString *msg = @"INXAsyncSocketManuallyEvaluateTrust specified in tlsSettings,"
            @" but delegate doesn't implement socket:shouldTrustPeer:";
            
            [self closeWithError:[self otherError:msg]];
            return;
        }
    }
    else if (status == errSSLWouldBlock)
    {
        LogVerbose(@"SSLHandshake continues...");
        
        // 握手还在继续……
        //
        // 此方法将再次从doReadData或doWriteData调用。
    }
    else
    {
        [self closeWithError:[self sslError:status]];
    }
}

- (void)ssl_shouldTrustPeer:(BOOL)shouldTrust stateIndex:(int)aStateIndex
{
    LogTrace();
    
    if (aStateIndex != stateIndex)
    {
        LogInfo(@"Ignoring ssl_shouldTrustPeer - invalid state (maybe disconnected)");
        
        // 以下其中一条是正确的
        //  -插座断开了
        //  - startTLS操作超时
        //  - completionHandler已经被调用过一次
        
        return;
    }
    
    //增量状态索引，以确保completionHandler只能被调用一次。
    stateIndex++;
    
    if (shouldTrust)
    {
        NSAssert(lastSSLHandshakeError == errSSLPeerAuthCompleted, @"ssl_shouldTrustPeer called when last error is %d and not errSSLPeerAuthCompleted", (int)lastSSLHandshakeError);
        [self ssl_continueSSLHandshake];
    }
    else
    {
        [self closeWithError:[self sslError:errSSLPeerBadCert]];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

- (void)cf_finishSSLHandshake
{
    LogTrace();
    
    if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
    {
        flags &= ~kStartingReadTLS;
        flags &= ~kStartingWriteTLS;
        
        flags |= kSocketSecure;
        
        __strong id theDelegate = delegate;
        
        if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
        {
            dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
                [theDelegate socketDidSecure:self];
            }});
        }
        
        [self endCurrentRead];
        [self endCurrentWrite];
        
        [self maybeDequeueRead];
        [self maybeDequeueWrite];
    }
}

- (void)cf_abortSSLHandshake:(NSError *)error
{
    LogTrace();
    
    if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
    {
        flags &= ~kStartingReadTLS;
        flags &= ~kStartingWriteTLS;
        
        [self closeWithError:error];
    }
}

- (void)cf_startTLS
{
    LogTrace();
    
    LogVerbose(@"Starting TLS (via CFStream)...");
    
    if ([preBuffer availableBytes] > 0)
    {
        NSString *msg = @"Invalid TLS transition. Handshake has already been read from socket.";
        
        [self closeWithError:[self otherError:msg]];
        return;
    }
    
    [self suspendReadSource];
    [self suspendWriteSource];
    
    socketFDBytesAvailable = 0;
    flags &= ~kSocketCanAcceptBytes;
    flags &= ~kSecureSocketHasBytesAvailable;
    
    flags |=  kUsingCFStreamForTLS;
    
    if (![self createReadAndWriteStream])
    {
        [self closeWithError:[self otherError:@"Error in CFStreamCreatePairWithSocket"]];
        return;
    }
    
    if (![self registerForStreamCallbacksIncludingReadWrite:YES])
    {
        [self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
        return;
    }
    
    if (![self addStreamsToRunLoop])
    {
        [self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
        return;
    }
    
    NSAssert([currentRead isKindOfClass:[INXAsyncSpecialPacket class]], @"Invalid read packet for startTLS");
    NSAssert([currentWrite isKindOfClass:[INXAsyncSpecialPacket class]], @"Invalid write packet for startTLS");
    
    INXAsyncSpecialPacket *tlsPacket = (INXAsyncSpecialPacket *)currentRead;
    CFDictionaryRef tlsSettings = (__bridge CFDictionaryRef)tlsPacket->tlsSettings;
    
    // 得到关于kCFStreamPropertySSLSettings的错误?
    // 您需要将CFNetwork框架添加到iOS应用程序中。
    
    BOOL r1 = CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, tlsSettings);
    BOOL r2 = CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, tlsSettings);
    
    // 出于某种原因，从ios4.3开始，设置kCFStreamPropertySSLSettings的第一次调用将返回true，但第二次将返回false。
    //
    // 顺序似乎不重要。
    // 你可以调用CFReadStreamSetProperty然后调用CFWriteStreamSetProperty，或者你可以颠倒顺序。
    // 无论哪种方法，第一个调用将返回true，第二个调用将返回false。
    //
    // 有趣的是，这似乎没有影响任何事情。
    // 这并不完全是不寻常的，因为文档似乎表明(对于许多设置)将其设置在流的一边会自动将其设置为流的另一边。
    //
    // 尽管文档中没有任何内容表明第二次尝试会失败。
    //
    // 此外，这似乎只会影响正在协商安全升级的流。
    // 换句话说，套接字被连接，在不安全的连接上有一些来回通信，然后发出一个startTLS。
    // 因此，这主要影响较新的协议(XMPP、IMAP)，而不是较旧的协议(HTTPS)。
    
    if (!r1 && !r2) // 是的，&&是正确的-解决apple bug的方法。
    {
        [self closeWithError:[self otherError:@"Error in CFStreamSetProperty"]];
        return;
    }
    
    if (![self openStreams])
    {
        [self closeWithError:[self otherError:@"Error in CFStreamOpen"]];
        return;
    }
    
    LogVerbose(@"Waiting for SSL Handshake to complete...");
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

+ (void)ignore:(id)_
{}

+ (void)startCFStreamThreadIfNeeded
{
    LogTrace();
    
    static dispatch_once_t predicate;
    dispatch_once(&predicate, ^{
        
        cfstreamThreadRetainCount = 0;
        cfstreamThreadSetupQueue = dispatch_queue_create("INXAsyncSocket-CFStreamThreadSetup", DISPATCH_QUEUE_SERIAL);
    });
    
    dispatch_sync(cfstreamThreadSetupQueue, ^{ @autoreleasepool {
        
        if (++cfstreamThreadRetainCount == 1)
        {
            cfstreamThread = [[NSThread alloc] initWithTarget:self
                                                     selector:@selector(cfstreamThread)
                                                       object:nil];
            [cfstreamThread start];
        }
    }});
}

+ (void)stopCFStreamThreadIfNeeded
{
    LogTrace();
    
    //创建cfstreamThread的成本相对较高。
    //所以我们想把它回收利用。
    //然而，这里有一个权衡，因为它不应该永远活着。
    //因此，我们要做的是在把它取下来之前使用一点延迟。
    //这样就可以在多个插座不断变化的情况下正确地重用它。
    
    int delayInSeconds = 30;
    dispatch_time_t when = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
    dispatch_after(when, cfstreamThreadSetupQueue, ^{ @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        
        if (cfstreamThreadRetainCount == 0)
        {
            LogWarn(@"Logic error concerning cfstreamThread start / stop");
            return_from_block;
        }
        
        if (--cfstreamThreadRetainCount == 0)
        {
            [cfstreamThread cancel]; // set isCancelled flag
            
            // wake up the thread
            [[self class] performSelector:@selector(ignore:)
                                 onThread:cfstreamThread
                               withObject:[NSNull null]
                            waitUntilDone:NO];
            
            cfstreamThread = nil;
        }
        
#pragma clang diagnostic pop
    }});
}

+ (void)cfstreamThread { @autoreleasepool
    {
        [[NSThread currentThread] setName:INXAsyncSocketThreadName];
        
        LogInfo(@"CFStreamThread: Started");
        
        //我们不能运行runloop，除非它有一个相关的输入源或计时器。
        //因此，我们将创建一个永不触发的计时器——除非服务器运行数十年。
        [NSTimer scheduledTimerWithTimeInterval:[[NSDate distantFuture] timeIntervalSinceNow]
                                         target:self
                                       selector:@selector(ignore:)
                                       userInfo:nil
                                        repeats:YES];
        
        NSThread *currentThread = [NSThread currentThread];
        NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
        
        BOOL isCancelled = [currentThread isCancelled];
        
        while (!isCancelled && [currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
        {
            isCancelled = [currentThread isCancelled];
        }
        
        LogInfo(@"CFStreamThread: Stopped");
    }}

+ (void)scheduleCFStreams:(INXAsyncSocket *)asyncSocket
{
    LogTrace();
    NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
    
    CFRunLoopRef runLoop = CFRunLoopGetCurrent();
    
    if (asyncSocket->readStream)
        CFReadStreamScheduleWithRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
    
    if (asyncSocket->writeStream)
        CFWriteStreamScheduleWithRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

+ (void)unscheduleCFStreams:(INXAsyncSocket *)asyncSocket
{
    LogTrace();
    NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
    
    CFRunLoopRef runLoop = CFRunLoopGetCurrent();
    
    if (asyncSocket->readStream)
        CFReadStreamUnscheduleFromRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
    
    if (asyncSocket->writeStream)
        CFWriteStreamUnscheduleFromRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

static void CFReadStreamCallback (CFReadStreamRef stream, CFStreamEventType type, void *pInfo)
{
    INXAsyncSocket *asyncSocket = (__bridge INXAsyncSocket *)pInfo;
    
    switch(type)
    {
        case kCFStreamEventHasBytesAvailable:
        {
            dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
                
                LogCVerbose(@"CFReadStreamCallback - HasBytesAvailable");
                
                if (asyncSocket->readStream != stream)
                    return_from_block;
                
                if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
                {
                    // 如果在打开流之前设置kCFStreamPropertySSLSettings，这可能是一个谎言。
                    // (与tcp流相关的回调，但与SSL层无关)。
                    
                    if (CFReadStreamHasBytesAvailable(asyncSocket->readStream))
                    {
                        asyncSocket->flags |= kSecureSocketHasBytesAvailable;
                        [asyncSocket cf_finishSSLHandshake];
                    }
                }
                else
                {
                    asyncSocket->flags |= kSecureSocketHasBytesAvailable;
                    [asyncSocket doReadData];
                }
            }});
            
            break;
        }
        default:
        {
            NSError *error = (__bridge_transfer  NSError *)CFReadStreamCopyError(stream);
            
            if (error == nil && type == kCFStreamEventEndEncountered)
            {
                error = [asyncSocket connectionClosedError];
            }
            
            dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
                
                LogCVerbose(@"CFReadStreamCallback - Other");
                
                if (asyncSocket->readStream != stream)
                    return_from_block;
                
                if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
                {
                    [asyncSocket cf_abortSSLHandshake:error];
                }
                else
                {
                    [asyncSocket closeWithError:error];
                }
            }});
            
            break;
        }
    }
    
}

static void CFWriteStreamCallback (CFWriteStreamRef stream, CFStreamEventType type, void *pInfo)
{
    INXAsyncSocket *asyncSocket = (__bridge INXAsyncSocket *)pInfo;
    
    switch(type)
    {
        case kCFStreamEventCanAcceptBytes:
        {
            dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
                
                LogCVerbose(@"CFWriteStreamCallback - CanAcceptBytes");
                
                if (asyncSocket->writeStream != stream)
                    return_from_block;
                
                if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
                {
                    // 如果在打开流之前设置kCFStreamPropertySSLSettings，这可能是假的。
                    // (与tcp流相关的回调，但与SSL层无关)。
                    
                    if (CFWriteStreamCanAcceptBytes(asyncSocket->writeStream))
                    {
                        asyncSocket->flags |= kSocketCanAcceptBytes;
                        [asyncSocket cf_finishSSLHandshake];
                    }
                }
                else
                {
                    asyncSocket->flags |= kSocketCanAcceptBytes;
                    [asyncSocket doWriteData];
                }
            }});
            
            break;
        }
        default:
        {
            NSError *error = (__bridge_transfer NSError *)CFWriteStreamCopyError(stream);
            
            if (error == nil && type == kCFStreamEventEndEncountered)
            {
                error = [asyncSocket connectionClosedError];
            }
            
            dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
                
                LogCVerbose(@"CFWriteStreamCallback - Other");
                
                if (asyncSocket->writeStream != stream)
                    return_from_block;
                
                if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
                {
                    [asyncSocket cf_abortSSLHandshake:error];
                }
                else
                {
                    [asyncSocket closeWithError:error];
                }
            }});
            
            break;
        }
    }
    
}

- (BOOL)createReadAndWriteStream
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    
    
    if (readStream || writeStream)
    {
        // Streams already created
        return YES;
    }
    
    int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
    
    if (socketFD == SOCKET_NULL)
    {
        // Cannot create streams without a file descriptor
        return NO;
    }
    
    if (![self isConnected])
    {
        // Cannot create streams until file descriptor is connected
        return NO;
    }
    
    LogVerbose(@"Creating read and write stream...");
    
    CFStreamCreatePairWithSocket(NULL, (CFSocketNativeHandle)socketFD, &readStream, &writeStream);
    
    // kCFStreamPropertyShouldCloseNativeSocket属性默认为false(对于我们的示例)。但是我们不要冒任何风险。
    
    if (readStream)
        CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
    if (writeStream)
        CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
    
    if ((readStream == NULL) || (writeStream == NULL))
    {
        LogWarn(@"Unable to create read and write stream...");
        
        if (readStream)
        {
            CFReadStreamClose(readStream);
            CFRelease(readStream);
            readStream = NULL;
        }
        if (writeStream)
        {
            CFWriteStreamClose(writeStream);
            CFRelease(writeStream);
            writeStream = NULL;
        }
        
        return NO;
    }
    
    return YES;
}

- (BOOL)registerForStreamCallbacksIncludingReadWrite:(BOOL)includeReadWrite
{
    LogVerbose(@"%@ %@", THIS_METHOD, (includeReadWrite ? @"YES" : @"NO"));
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
    
    streamContext.version = 0;
    streamContext.info = (__bridge void *)(self);
    streamContext.retain = nil;
    streamContext.release = nil;
    streamContext.copyDescription = nil;
    
    CFOptionFlags readStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
    if (includeReadWrite)
        readStreamEvents |= kCFStreamEventHasBytesAvailable;
    
    if (!CFReadStreamSetClient(readStream, readStreamEvents, &CFReadStreamCallback, &streamContext))
    {
        return NO;
    }
    
    CFOptionFlags writeStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
    if (includeReadWrite)
        writeStreamEvents |= kCFStreamEventCanAcceptBytes;
    
    if (!CFWriteStreamSetClient(writeStream, writeStreamEvents, &CFWriteStreamCallback, &streamContext))
    {
        return NO;
    }
    
    return YES;
}

- (BOOL)addStreamsToRunLoop
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
    
    if (!(flags & kAddedStreamsToRunLoop))
    {
        LogVerbose(@"Adding streams to runloop...");
        
        [[self class] startCFStreamThreadIfNeeded];
        dispatch_sync(cfstreamThreadSetupQueue, ^{
            [[self class] performSelector:@selector(scheduleCFStreams:)
                                 onThread:cfstreamThread
                               withObject:self
                            waitUntilDone:YES];
        });
        flags |= kAddedStreamsToRunLoop;
    }
    
    return YES;
}

- (void)removeStreamsFromRunLoop
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
    
    if (flags & kAddedStreamsToRunLoop)
    {
        LogVerbose(@"Removing streams from runloop...");
        
        dispatch_sync(cfstreamThreadSetupQueue, ^{
            [[self class] performSelector:@selector(unscheduleCFStreams:)
                                 onThread:cfstreamThread
                               withObject:self
                            waitUntilDone:YES];
        });
        [[self class] stopCFStreamThreadIfNeeded];
        
        flags &= ~kAddedStreamsToRunLoop;
    }
}

- (BOOL)openStreams
{
    LogTrace();
    
    NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
    
    CFStreamStatus readStatus = CFReadStreamGetStatus(readStream);
    CFStreamStatus writeStatus = CFWriteStreamGetStatus(writeStream);
    
    if ((readStatus == kCFStreamStatusNotOpen) || (writeStatus == kCFStreamStatusNotOpen))
    {
        LogVerbose(@"Opening read and write stream...");
        
        BOOL r1 = CFReadStreamOpen(readStream);
        BOOL r2 = CFWriteStreamOpen(writeStream);
        
        if (!r1 || !r2)
        {
            LogError(@"Error in CFStreamOpen");
            return NO;
        }
    }
    
    return YES;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Advanced
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * See header file for big discussion of this method.
 **/
- (BOOL)autoDisconnectOnClosedReadStream
{
    // Note: YES means kAllowHalfDuplexConnection is OFF
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        return ((config & kAllowHalfDuplexConnection) == 0);
    }
    else
    {
        __block BOOL result;
        
        dispatch_sync(socketQueue, ^{
            result = ((self->config & kAllowHalfDuplexConnection) == 0);
        });
        
        return result;
    }
}

/**
 * See header file for big discussion of this method.
 **/
- (void)setAutoDisconnectOnClosedReadStream:(BOOL)flag
{
    // Note: YES means kAllowHalfDuplexConnection is OFF
    
    dispatch_block_t block = ^{
        
        if (flag)
            self->config &= ~kAllowHalfDuplexConnection;
        else
            self->config |= kAllowHalfDuplexConnection;
    };
    
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_async(socketQueue, block);
}


/**
 * See header file for big discussion of this method.
 **/
- (void)markSocketQueueTargetQueue:(dispatch_queue_t)socketNewTargetQueue
{
    void *nonNullUnusedPointer = (__bridge void *)self;
    dispatch_queue_set_specific(socketNewTargetQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
}

/**
 * See header file for big discussion of this method.
 **/
- (void)unmarkSocketQueueTargetQueue:(dispatch_queue_t)socketOldTargetQueue
{
    dispatch_queue_set_specific(socketOldTargetQueue, IsOnSocketQueueOrTargetQueueKey, NULL, NULL);
}

/**
 * See header file for big discussion of this method.
 **/
- (void)performBlock:(dispatch_block_t)block
{
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        dispatch_sync(socketQueue, block);
}

/**
 * Questions? Have you read the header file?
 **/
- (int)socketFD
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return SOCKET_NULL;
    }
    
    if (socket4FD != SOCKET_NULL)
        return socket4FD;
    else
        return socket6FD;
}

/**
 * Questions? Have you read the header file?
 **/
- (int)socket4FD
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return SOCKET_NULL;
    }
    
    return socket4FD;
}

/**
 * Questions? Have you read the header file?
 **/
- (int)socket6FD
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return SOCKET_NULL;
    }
    
    return socket6FD;
}

#if TARGET_OS_IPHONE

/**
 * Questions? Have you read the header file?
 **/
- (CFReadStreamRef)readStream
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return NULL;
    }
    
    if (readStream == NULL)
        [self createReadAndWriteStream];
    
    return readStream;
}

/**
 * Questions? Have you read the header file?
 **/
- (CFWriteStreamRef)writeStream
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return NULL;
    }
    
    if (writeStream == NULL)
        [self createReadAndWriteStream];
    
    return writeStream;
}

- (BOOL)enableBackgroundingOnSocketWithCaveat:(BOOL)caveat
{
    if (![self createReadAndWriteStream])
    {
        // Error occurred creating streams (perhaps socket isn't open)
        return NO;
    }
    
    BOOL r1, r2;
    LogVerbose(@"Enabling backgrouding on socket");
    
    r1 = CFReadStreamSetProperty(readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
    r2 = CFWriteStreamSetProperty(writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
    
    if (!r1 || !r2)
    {
        return NO;
    }
    
    if (!caveat)
    {
        if (![self openStreams])
        {
            return NO;
        }
    }
    
    return YES;
}

/**
 * Questions? Have you read the header file?
 **/
- (BOOL)enableBackgroundingOnSocket
{
    LogTrace();
    
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return NO;
    }
    
    return [self enableBackgroundingOnSocketWithCaveat:NO];
}

- (BOOL)enableBackgroundingOnSocketWithCaveat // Deprecated in iOS 4.???
{
    // This method was created as a workaround for a bug in iOS.
    // Apple has since fixed this bug.
    // I'm not entirely sure which version of iOS they fixed it in...
    
    LogTrace();
    
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return NO;
    }
    
    return [self enableBackgroundingOnSocketWithCaveat:YES];
}

#endif

- (SSLContextRef)sslContext
{
    if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
    {
        LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
        return NULL;
    }
    
    return sslContext;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Class Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 创建服务端地址数据
 
 @param host 服务端host
 @param port 服务端 port
 @param errPtr 待填充错误
 @return 服务端地址信息结构体
 */
+ (NSMutableArray *)lookupHost:(NSString *)host port:(uint16_t)port error:(NSError **)errPtr
{
    LogTrace();
    
    NSMutableArray *addresses = nil;
    NSError *error = nil;
    //本机地址及路由回环虚拟地址
    if ([host isEqualToString:@"localhost"] || [host isEqualToString:@"loopback"])
    {
        // Use LOOPBACK address
        struct sockaddr_in nativeAddr4;
        nativeAddr4.sin_len         = sizeof(struct sockaddr_in);
        nativeAddr4.sin_family      = AF_INET;
        nativeAddr4.sin_port        = htons(port);
        nativeAddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        memset(&(nativeAddr4.sin_zero), 0, sizeof(nativeAddr4.sin_zero));
        
        struct sockaddr_in6 nativeAddr6;
        nativeAddr6.sin6_len        = sizeof(struct sockaddr_in6);
        nativeAddr6.sin6_family     = AF_INET6;
        nativeAddr6.sin6_port       = htons(port);
        nativeAddr6.sin6_flowinfo   = 0;
        nativeAddr6.sin6_addr       = in6addr_loopback;
        nativeAddr6.sin6_scope_id   = 0;
        
        // Wrap the native address structures
        
        NSData *address4 = [NSData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
        NSData *address6 = [NSData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
        
        addresses = [NSMutableArray arrayWithCapacity:2];
        [addresses addObject:address4];
        [addresses addObject:address6];
    }
    else
    {
        NSString *portStr = [NSString stringWithFormat:@"%hu", port];
        
        struct addrinfo hints, *res, *res0;
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        
        int gai_error = getaddrinfo([host UTF8String], [portStr UTF8String], &hints, &res0);
        
        if (gai_error)
        {
            error = [self gaiError:gai_error];
        }
        else
        {
            NSUInteger capacity = 0;
            for (res = res0; res; res = res->ai_next)
            {
                if (res->ai_family == AF_INET || res->ai_family == AF_INET6) {
                    capacity++;
                }
            }
            
            addresses = [NSMutableArray arrayWithCapacity:capacity];
            
            for (res = res0; res; res = res->ai_next)
            {
                if (res->ai_family == AF_INET)
                {
                    // Found IPv4 address.
                    // Wrap the native address structure, and add to results.
                    
                    NSData *address4 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
                    [addresses addObject:address4];
                }
                else if (res->ai_family == AF_INET6)
                {
                    // Fixes connection issues with IPv6
                    // https://github.com/robbiehanson/CocoaAsyncSocket/issues/429#issuecomment-222477158
                    
                    // Found IPv6 address.
                    // Wrap the native address structure, and add to results.
                    
                    struct sockaddr_in6 *sockaddr = (struct sockaddr_in6 *)res->ai_addr;
                    in_port_t *portPtr = &sockaddr->sin6_port;
                    if ((portPtr != NULL) && (*portPtr == 0)) {
                        *portPtr = htons(port);
                    }
                    
                    NSData *address6 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
                    [addresses addObject:address6];
                }
            }
            freeaddrinfo(res0);
            
            if ([addresses count] == 0)
            {
                error = [self gaiError:EAI_FAIL];
            }
        }
    }
    
    if (errPtr) *errPtr = error;
    return addresses;
}

+ (NSString *)hostFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
    char addrBuf[INET_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET, &pSockaddr4->sin_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
    {
        addrBuf[0] = '\0';
    }
    
    return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

+ (NSString *)hostFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
    char addrBuf[INET6_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET6, &pSockaddr6->sin6_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
    {
        addrBuf[0] = '\0';
    }
    
    return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

+ (uint16_t)portFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
    return ntohs(pSockaddr4->sin_port);
}

+ (uint16_t)portFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
    return ntohs(pSockaddr6->sin6_port);
}

+ (NSURL *)urlFromSockaddrUN:(const struct sockaddr_un *)pSockaddr
{
    NSString *path = [NSString stringWithUTF8String:pSockaddr->sun_path];
    return [NSURL fileURLWithPath:path];
}

+ (NSString *)hostFromAddress:(NSData *)address
{
    NSString *host;
    
    if ([self getHost:&host port:NULL fromAddress:address])
        return host;
    else
        return nil;
}

+ (uint16_t)portFromAddress:(NSData *)address
{
    uint16_t port;
    
    if ([self getHost:NULL port:&port fromAddress:address])
        return port;
    else
        return 0;
}

+ (BOOL)isIPv4Address:(NSData *)address
{
    if ([address length] >= sizeof(struct sockaddr))
    {
        const struct sockaddr *sockaddrX = [address bytes];
        
        if (sockaddrX->sa_family == AF_INET) {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)isIPv6Address:(NSData *)address
{
    if ([address length] >= sizeof(struct sockaddr))
    {
        const struct sockaddr *sockaddrX = [address bytes];
        
        if (sockaddrX->sa_family == AF_INET6) {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr fromAddress:(NSData *)address
{
    return [self getHost:hostPtr port:portPtr family:NULL fromAddress:address];
}

+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr family:(sa_family_t *)afPtr fromAddress:(NSData *)address
{
    if ([address length] >= sizeof(struct sockaddr))
    {
        const struct sockaddr *sockaddrX = [address bytes];
        
        if (sockaddrX->sa_family == AF_INET)
        {
            if ([address length] >= sizeof(struct sockaddr_in))
            {
                struct sockaddr_in sockaddr4;
                memcpy(&sockaddr4, sockaddrX, sizeof(sockaddr4));
                
                if (hostPtr) *hostPtr = [self hostFromSockaddr4:&sockaddr4];
                if (portPtr) *portPtr = [self portFromSockaddr4:&sockaddr4];
                if (afPtr)   *afPtr   = AF_INET;
                
                return YES;
            }
        }
        else if (sockaddrX->sa_family == AF_INET6)
        {
            if ([address length] >= sizeof(struct sockaddr_in6))
            {
                struct sockaddr_in6 sockaddr6;
                memcpy(&sockaddr6, sockaddrX, sizeof(sockaddr6));
                
                if (hostPtr) *hostPtr = [self hostFromSockaddr6:&sockaddr6];
                if (portPtr) *portPtr = [self portFromSockaddr6:&sockaddr6];
                if (afPtr)   *afPtr   = AF_INET6;
                
                return YES;
            }
        }
    }
    
    return NO;
}

+ (NSData *)CRLFData
{
    return [NSData dataWithBytes:"\x0D\x0A" length:2];
}

+ (NSData *)CRData
{
    return [NSData dataWithBytes:"\x0D" length:1];
}

+ (NSData *)LFData
{
    return [NSData dataWithBytes:"\x0A" length:1];
}

+ (NSData *)ZeroData
{
    return [NSData dataWithBytes:"" length:1];
}

@end

