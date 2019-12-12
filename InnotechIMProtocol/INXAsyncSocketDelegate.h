//
//  INXAsyncSocketDelegate.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol INXAsyncSocketDelegate <NSObject>
@optional

/**
 * 此方法在socket:didAcceptNewSocket:之前立即调用。
 * 它可选地允许监听socket为新接受的socket指定socketQueue。
 * 如果这个方法没有实现，或者返回NULL，新的接受socket将创建它自己的默认队列。
 *
 * 由于无法自动释放dispatch_queue，
 * 此方法在其名称中使用“new”前缀来指定已保留返回的队列。
 *
 * 因此，您可以在实现中这样做:
 * return dispatch_queue_create("MyQueue", NULL);
 *
 * 如果在同一个队列中放置多个socket，
 * 应该注意在每次调用此方法时增加retain count。
 *
 * 例如，您的实现可能是这样的:
 * dispatch_retain(myExistingQueue);
 * return myExistingQueue;
 **/
- (nullable dispatch_queue_t)newSocketQueueForConnectionFromAddress:(NSData *)address onSocket:(INXAsyncSocket *)sock;

/**
 * 当socket接受连接时调用。
 * 自动生成另一个socket来处理它。
 *
 * 如果希望处理连接，则必须保留newSocket。
 * 否则，newSocket实例将被释放，派生的连接将被关闭。
 *
 * 默认情况下，新的socket将具有相同的委托和delegateQueue。
 * 当然，您可以随时更改此选项.
 **/
- (void)socket:(INXAsyncSocket *)sock didAcceptNewSocket:(INXAsyncSocket *)newSocket;

/**
 * 当socket连接并准备读写时调用。
 * 主机参数将是IP地址，而不是DNS名称。
 **/
- (void)socket:(INXAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port;

/**
 * 当socket连接并准备读写时调用。
 * 主机参数将是IP地址，而不是DNS名称。
 **/
- (void)socket:(INXAsyncSocket *)sock didConnectToUrl:(NSURL *)url;

/**
 * 当socket完成将请求的数据读入内存时调用。
 * 如果有错误，则不调用。
 **/
- (void)socket:(INXAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag;

/**
 * 当socket已读取数据，但尚未完成读取时调用。
 * 如果使用readToData:或readToLength:方法，就会发生这种情况。
 * 它可能用于更新进度条之类的事情。
 **/
- (void)socket:(INXAsyncSocket *)sock didReadPartialDataOfLength:(NSUInteger)partialLength tag:(long)tag;

/**
 * 当socket完成写入请求的数据时调用。如果有错误，则不调用。
 **/
- (void)socket:(INXAsyncSocket *)sock didWriteDataWithTag:(long)tag;

/**
 * 当socket已写入一些数据，但尚未完成全部写入时调用。
 * 它可能用于更新进度条之类的事情。
 **/
- (void)socket:(INXAsyncSocket *)sock didWritePartialDataOfLength:(NSUInteger)partialLength tag:(long)tag;

/**
 * 如果读取操作未完成而达到超时，则调用。
 * 此方法允许您选择性地扩展超时。
 * 如果返回一个正的时间间隔(> 0)，则读取的超时将延长给定的时间量。
 * 如果不实现此方法，或者返回非正时间间隔(<= 0)，读取将像往常一样超时。
 *
 * elapsed参数是原始超时的和，加上之前通过该方法添加的任何内容。
 * length参数是到目前为止为read操作读取的字节数。
 *
 * 注意，如果返回的是正数，那么在一次读取中可能会多次调用此方法。
 **/
- (NSTimeInterval)socket:(INXAsyncSocket *)sock shouldTimeoutReadWithTag:(long)tag
                 elapsed:(NSTimeInterval)elapsed
               bytesDone:(NSUInteger)length;

/**
 * 如果写入操作未完成而达到超时，则调用（同上）。
 **/
- (NSTimeInterval)socket:(INXAsyncSocket *)sock shouldTimeoutWriteWithTag:(long)tag
                 elapsed:(NSTimeInterval)elapsed
               bytesDone:(NSUInteger)length;

/**
 * 如果读流关闭，则有条件地调用，但写流仍然是可写的。
 *
 * 只有当`autoDisconnectOnClosedReadStream`被设置为NO时，才调用此委托方法。
 * 有关更多信息，请参阅关于`autoDisconnectOnClosedReadStream`方法的讨论。
 **/
- (void)socketDidCloseReadStream:(INXAsyncSocket *)sock;

/**
 * 当socket断开连接时调用，无论是否有错误。
 *
 * 如果您调用了disconnect方法，而socket尚未断开连接，则在disconnect方法返回之前，对这个委托方法的调用将被排队到delegateQueue上。
 *
 * 注意:如果INXAsyncSocket实例在它仍然连接的时候被释放，并且委托也没有被释放，那么这个方法将被调用，
 * 但是sock参数将为nil。(它必须是nil，因为它不再可用。)
 * 这通常是罕见的，但如果有人这样写代码，这是可能的:
 *
 **/
- (void)socketDidDisconnect:(INXAsyncSocket *)sock withError:(nullable NSError *)err;

/**
 * socket成功完成SSL/TLS协商后调用。
 * 除非使用提供的startTLS方法，否则不会调用此方法。
 *
 * 如果SSL/TLS协商失败(证书无效等)，socket将立即关闭。
 * 并且socketDidDisconnect:with error: delegate方法将使用特定的SSL错误代码调用。
 **/
- (void)socketDidSecure:(INXAsyncSocket *)sock;

/**
 * 允许socket委托挂钩到TLS握手并手动验证它所连接的对等点。
 *
 * 只有在使用以下选项调用startTLS时才调用此函数:
 * - INXAsyncSocketManuallyEvaluateTrust == YES
 *
 * 通常，委托将使用SecTrustEvaluate(和相关函数)正确地验证对等方。
 *
 * 来自苹果文档的说明:
 *   因为[SecTrustEvaluate]可能会在网络上查找证书链中的证书，[它]可能在尝试网络访问时阻塞。
 *   永远不要从主线程调用它，仅在运行在分派队列或单独线程上的函数中调用它。
 *
 * 因此，该方法使用completionHandler块而不是普通的返回值。
 * completionHandler块是线程安全的，可以从后台队列/线程调用。
 * 即使socket已经关闭，调用completionHandler块也是安全的。
 **/
- (void)socket:(INXAsyncSocket *)sock didReceiveTrust:(SecTrustRef)trust completionHandler:(void (^)(BOOL shouldTrustPeer))completionHandler;
@end

NS_ASSUME_NONNULL_END
