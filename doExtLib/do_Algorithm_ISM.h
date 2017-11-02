//
//  do_Algorithm_IMethod.h
//  DoExt_API
//
//  Created by @userName on @time.
//  Copyright (c) 2015年 DoExt. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol do_Algorithm_ISM <NSObject>

//实现同步或异步方法，parms中包含了所需用的属性
@required
- (void)base64:(NSArray *)parms;
- (void)base64Sync:(NSArray *)parms;
- (void)des3:(NSArray *)parms;
- (void)des3Sync:(NSArray *)parms;
- (void)md5:(NSArray *)parms;
- (void)md5Sync:(NSArray *)parms;
- (void)sha1:(NSArray *)parms;
- (void)sha1Sync:(NSArray *)parms;
- (void)hex2Binary:(NSArray *)parms;
- (void)hex2Str:(NSArray *)parms;
- (void)xml2Json:(NSArray *)parms;

@end