//
//  INXAsyncSocketPreBuffer.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/**
 * 当socket上的可用数据多于当前读请求请求的数据时，使用预缓冲区。
 * 在这种情况下，我们从socket中吸收所有数据(以最小化系统调用)，并将额外的未读数据存储在“预缓冲区”中。
 *
 * 在再次从socket读取之前，预缓冲区已完全耗尽。换句话说，一大块数据被写入预缓冲区。
 * 然后通过一系列的一次或多次读取(用于后续的读取请求)清空预缓冲区。
 *
 * 环缓冲区曾经用于此目的。
 * 但是，环形缓冲区占用的内存是所需内存的两倍(镜像占用的内存是所需内存的两倍)。
 * 实际上，它通常占用所需大小的两倍以上，因为所有内容都必须四舍五入到vm_page_size。
 * 由于预缓冲区总是在写入后完全耗尽，所以不需要完整的环形缓冲区。
 *
 * 目前的设计非常简单和直接，同时也保持较低的内存需求。
 **/
@interface INXAsyncSocketPreBuffer : NSObject
{
    uint8_t *preBuffer;
    size_t preBufferSize;
    
    uint8_t *readPointer;
    uint8_t *writePointer;
}

- (id)initWithCapacity:(size_t)numBytes;

- (void)ensureCapacityForWrite:(size_t)numBytes;

- (size_t)availableBytes;
- (uint8_t *)readBuffer;

- (void)getReadBuffer:(uint8_t **)bufferPtr availableBytes:(size_t *)availableBytesPtr;

- (size_t)availableSpace;
- (uint8_t *)writeBuffer;

- (void)getWriteBuffer:(uint8_t **)bufferPtr availableSpace:(size_t *)availableSpacePtr;

- (void)didRead:(size_t)bytesRead;
- (void)didWrite:(size_t)bytesWritten;

- (void)reset;
@end

NS_ASSUME_NONNULL_END
