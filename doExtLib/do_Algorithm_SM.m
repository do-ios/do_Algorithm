//
//  do_Algorithm_MM.m
//  DoExt_MM
//
//  Created by @userName on @time.
//  Copyright (c) 2015年 DoExt. All rights reserved.
//

#import "do_Algorithm_SM.h"
#import "doScriptEngineHelper.h"
#import "doIScriptEngine.h"
#import "doInvokeResult.h"
#import <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#import "doIOHelper.h"
#import "doTextHelper.h"
#import "doUIModuleHelper.h"
#import "doJsonHelper.h"
#import "doServiceContainer.h"
#import "doILogEngine.h"
#import "doXMLReader.h"

#define FileHashDefaultChunkSizeForReadingData 1024*8
#define gIv @"01234567"
static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

@implementation do_Algorithm_SM

#pragma mark - 注册属性（--属性定义--）
/*
 [self RegistProperty:[[doProperty alloc]init:@"属性名" :属性类型 :@"默认值" : BOOL:是否支持代码修改属性]];
 */
-(void)OnInit
{
    [super OnInit];
    //注册属性
}

//销毁所有的全局对象
-(void)Dispose
{
    //(self)类销毁时会调用递归调用该方法，在该类中主动生成的非原生的扩展对象需要主动调该方法使其销毁
}
#pragma mark -
#pragma mark - 同步异步方法的实现
//同步
//同步
- (void)base64Sync:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    //自己的代码实现
    doInvokeResult *_invokeResult = [parms objectAtIndex:2];
    //_invokeResult设置返回值
    
    NSString *type = [doJsonHelper GetOneText:_dictParas :@"type" :@"encode"];
    NSString *source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    if ([type isEqualToString:@"encode"])
    {
        // 加密
        NSData *data = [source dataUsingEncoding:NSUTF8StringEncoding];
        [_invokeResult SetResultText: [data base64EncodedStringWithOptions:0]];
    }
    else
    {
        //解密
        NSData *data = [do_Algorithm_SM dataWithBase64EncodedString:source];
        [_invokeResult SetResultText:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
    }
}

- (void)des3Sync:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    //自己的代码实现
    doInvokeResult *_invokeResult = [parms objectAtIndex:2];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"type" :@"encrypt"];
    NSString *sourceKey = [doJsonHelper GetOneText:_dictParas :@"key" :@""];
    NSString *Source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    if ([sourceType isEqualToString:@"encrypt"]) {
        //加密
        NSString* cryData = [self EncriptData:[Source dataUsingEncoding:NSUTF8StringEncoding] :sourceKey];
        [_invokeResult SetResultText: cryData];
    }
    else
    {
        NSData *data = [do_Algorithm_SM dataWithBase64EncodedString:Source];
        NSString* resultStr = [self DecriptData:data :sourceKey];
        [_invokeResult SetResultText: resultStr];
    }
}

- (void)des3:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"type" :@"encrypt"];
    NSString *sourceKey = [doJsonHelper GetOneText:_dictParas :@"key" :@""];
    NSString *Source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    if ([sourceType isEqualToString:@"encrypt"]) {
        //加密
        NSString* cryData = [self EncriptData:[Source dataUsingEncoding:NSUTF8StringEncoding] :sourceKey];
        [_invokeResult SetResultText: cryData];
        [_scritEngine Callback:_callbackName :_invokeResult];
    }
    else
    {
        NSData *data = [do_Algorithm_SM dataWithBase64EncodedString:Source];
        NSString * resultStr = [self DecriptData:data :sourceKey];
        [_invokeResult SetResultText: resultStr];
        [_scritEngine Callback:_callbackName :_invokeResult];
    }
}

- (void)md5Sync:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    //自己的代码实现
    
    doInvokeResult *_invokeResult = [parms objectAtIndex:2];
    //_invokeResult设置返回值
    
    NSString *sourceValue = [doJsonHelper GetOneText:_dictParas :@"value" :@""];
    NSString *outputString;
    outputString = [self getmd5FromTextOrString:sourceValue];
    [_invokeResult SetResultText:outputString];
}

- (void)sha1Sync:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    //自己的代码实现
    
    doInvokeResult *_invokeResult = [parms objectAtIndex:2];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"type" :@"lowercase"];
    NSString *sourceValue = [doJsonHelper GetOneText:_dictParas :@"value" :@""];
    
    const char *cstr = [sourceValue cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:sourceValue.length];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
    {
        [output appendFormat:@"%02x", digest[i]];
    }
    NSString *outputString;
    if ((sourceType.length >0) && [sourceType isEqualToString:@"lowercase"])
    {
        outputString = [output lowercaseString];
    }
    else if ((sourceType.length >0) && [sourceType isEqualToString:@"uppercase"])
    {
        outputString = [output uppercaseString];
    }
    [_invokeResult SetResultText: outputString];
}

//异步
- (void)hex2Binary:(NSArray *)parms
{
    //异步耗时操作，但是不需要启动线程，框架会自动加载一个后台线程处理这个函数
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    NSString *source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    NSString *path = [doJsonHelper GetOneText:_dictParas :@"path" :@""];
    NSString *localPath = [doIOHelper GetLocalFileFullPath:_scritEngine.CurrentApp :path];
    NSError *error = nil;
    NSString *finder = [localPath stringByDeletingLastPathComponent];
    if (![doIOHelper ExistDirectory:finder]) {
        [doIOHelper CreateDirectory:finder];
    }

    NSData *data = [self convertHexStrToData:source];
    [data writeToFile:localPath atomically:YES];
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    if (error) {
        [_invokeResult SetResultBoolean:NO];
    }
    else
    {
        [_invokeResult SetResultBoolean:YES];
    }
    
    [_scritEngine Callback:_callbackName :_invokeResult];
}
- (void)hex2Str:(NSArray *)parms
{
    //异步耗时操作，但是不需要启动线程，框架会自动加载一个后台线程处理这个函数
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    
    NSString *source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    
    NSString *encoding = [doJsonHelper GetOneText:_dictParas :@"encoding" :@"utf-8"];
    
    NSData *data = [self convertHexStrToData:source];
    
    NSStringEncoding encode = [self getEncodingWithString:encoding];
    
    NSString *result = [[NSString alloc]initWithData:data encoding:encode];
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    [_invokeResult SetResultText:result];
    [_scritEngine Callback:_callbackName :_invokeResult];
}
- (NSStringEncoding)getEncodingWithString:(NSString *)encode
{
    @try {
        CFStringRef aCFString = (__bridge CFStringRef)encode;
        CFStringEncoding cfEncoding = CFStringConvertIANACharSetNameToEncoding(aCFString);
        NSStringEncoding encoding = CFStringConvertEncodingToNSStringEncoding(cfEncoding);
        return encoding;
    } @catch (NSException *exception) {
        
        [[doServiceContainer Instance].LogEngine WriteError:exception :exception.description];
        doInvokeResult* _result = [[doInvokeResult alloc]init];
        [_result SetException:exception];
        return NSUTF8StringEncoding;
    }
}

- (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}

- (void)base64:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"sourceType" :@"string"];
    NSString *type = [doJsonHelper GetOneText:_dictParas :@"type" :@"encode"];
    NSString *source = [doJsonHelper GetOneText:_dictParas :@"source" :@""];
    
    if ([sourceType isEqual:@"file"])
    {
        //读文件转base64
        if ([type isEqualToString:@"encode"]) {
            //加密
            NSString *imgPath = [doIOHelper GetLocalFileFullPath:_scritEngine.CurrentApp :source];
            NSData *data = [NSData dataWithContentsOfFile:imgPath];
            [_invokeResult SetResultText: [data base64EncodedStringWithOptions:0]];
            [_scritEngine Callback:_callbackName :_invokeResult];
        }
        else
        {
            //解密
            NSString *fileName = [doUIModuleHelper stringWithUUID];
            NSString *tempFilePath = [NSString stringWithFormat:@"data://temp/%@",fileName];
            NSString *fileFullPath = [doIOHelper GetLocalFileFullPath:_scritEngine.CurrentApp :tempFilePath];
            NSString *directoryPath = [doIOHelper GetLocalFileFullPath:_scritEngine.CurrentApp :@"data://temp"];
            NSData *data = [do_Algorithm_SM dataWithBase64EncodedString:source];
            
            NSFileManager *fileMgr = [NSFileManager defaultManager];
            if (![fileMgr fileExistsAtPath:directoryPath]) {
                [fileMgr createDirectoryAtPath:directoryPath withIntermediateDirectories:true attributes:nil error:nil];
            }
            
            if (![fileMgr fileExistsAtPath:fileFullPath])
            {
                //创建一个文件
                if ([fileMgr createFileAtPath:fileFullPath contents:nil attributes:nil]) {
                    NSLog(@"创建数据文件成功");
                    if([data writeToFile:fileFullPath atomically:YES]) {
                        [_invokeResult SetResultText: tempFilePath];
                        [_scritEngine Callback:_callbackName :_invokeResult];
                    }
                }else {
                    NSLog(@"创建数据文件失败");
                    [_invokeResult SetResultText: @""];
                    [_scritEngine Callback:_callbackName :_invokeResult];
                    [[doServiceContainer Instance].LogEngine WriteError:nil :@"创建数据文件失败"];
                }
            }else {
                if(![data writeToFile:fileFullPath atomically:YES]) {
                    [[doServiceContainer Instance].LogEngine WriteError:nil :@"解密数据写入文件失败"];
                }
                [_invokeResult SetResultText: tempFilePath];
                [_scritEngine Callback:_callbackName :_invokeResult];
            }
           
            
        }
    }
    else
    {
        if ([type isEqualToString:@"encode"])
        {
            // 加密
            NSData *data = [source dataUsingEncoding:NSUTF8StringEncoding];
            [_invokeResult SetResultText: [data base64EncodedStringWithOptions:0]];
            [_scritEngine Callback:_callbackName :_invokeResult];
        }
        else
        {
            //解密
            NSData *data = [do_Algorithm_SM dataWithBase64EncodedString:source];
            [_invokeResult SetResultText:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
            [_scritEngine Callback:_callbackName :_invokeResult];
        }
    }
}

// 加密
-(NSString *) EncriptData:(NSData*)data :(NSString*)key
{
    size_t plainTextBufferSize = [data length];
    const void *vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [key UTF8String];

    const void *vinitVec = (const void *)[gIv UTF8String];

    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding,
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    NSString *result = [myData base64EncodedStringWithOptions:0];
    return result;
}

-(NSString *) DecriptData:(NSData *)encryptData :(NSString*)key
{
    size_t plainTextBufferSize = [encryptData length];
    const void *vplainText = [encryptData bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    const void *vkey = (const void *) [key UTF8String];
    const void *vinitVec = (const void *) [gIv UTF8String];
    
    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding,
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSString *result = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes] encoding:NSUTF8StringEncoding];
    return result;
}

- (void)md5:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"type" :@"string"];
    NSString *sourceValue = [doJsonHelper GetOneText:_dictParas :@"value" :@""];
    NSString *outputString;
    if ([sourceType isEqualToString:@"file"])
    {
        NSString *sourcePath = [doIOHelper GetLocalFileFullPath:_scritEngine.CurrentApp :sourceValue];
        outputString = [self getmd5FromFile:sourcePath];
    }
    else
    {
        outputString = [self getmd5FromTextOrString:sourceValue];
    }
    [_invokeResult SetResultText:outputString];
    [_scritEngine Callback:_callbackName :_invokeResult];
}

//处理字符串
-(NSString *)getmd5FromTextOrString:(NSString *)str {
    const char *cStr = [str UTF8String];//转换成utf-8
    unsigned char result[16];//开辟一个16字节（128位：md5加密出来就是128位/bit）的空间（一个字节=8字位=8个二进制数）
    CC_MD5( cStr, (CC_LONG)strlen(cStr), result);
    
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}

//处理文件
-(NSString *)getmd5FromFile:(NSString *)path
{
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if( handle== nil ) return @"ERROR GETTING FILE MD5"; // file didnt exist
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);

    BOOL done = NO;
    while(!done)
    {
        NSData* fileData = [handle readDataOfLength: FileHashDefaultChunkSizeForReadingData];
        CC_MD5_Update(&md5, [fileData bytes], (CC_LONG)[fileData length]);
        if( [fileData length] == 0 ) done = YES;
    }
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(result, &md5);
    
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}

- (void)sha1:(NSArray *)parms
{
    //异步耗时操作，但是不需要启动线程，框架会自动加载一个后台线程处理这个函数
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];
    //自己的代码实现
    
    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    //_invokeResult设置返回值
    NSString *sourceType = [doJsonHelper GetOneText:_dictParas :@"type" :@"lowercase"];
    NSString *sourceValue = [doJsonHelper GetOneText:_dictParas :@"value" :@""];
    
    const char *cstr = [sourceValue cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:sourceValue.length];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
    {
        [output appendFormat:@"%02x", digest[i]];
    }
    NSString *outputString;
    if ((sourceType.length >0) && [sourceType isEqualToString:@"lowercase"])
    {
        outputString = [output lowercaseString];
    }
    else if ((sourceType.length >0) && [sourceType isEqualToString:@"uppercase"])
    {
        outputString = [output uppercaseString];
    }
    [_invokeResult SetResultText: outputString];
    [_scritEngine Callback:_callbackName :_invokeResult];
}


+ (id)dataWithBase64EncodedString:(NSString *)string
{
    if (string == nil)
        [NSException raise:NSInvalidArgumentException format:@""];
    if ([string length] == 0)
        return [NSData data];
    
    static char *decodingTable = NULL;
    if (decodingTable == NULL)
    {
        decodingTable = malloc(256);
        if (decodingTable == NULL)
            return nil;
        memset(decodingTable, CHAR_MAX, 256);
        NSUInteger i;
        for (i = 0; i < 64; i++)
            decodingTable[(short)encodingTable[i]] = i;
    }
    
    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
    if (characters == NULL)     //  Not an ASCII string!
        return nil;
    char *bytes = malloc((([string length] + 3) / 4) * 3);
    if (bytes == NULL)
        return nil;
    NSUInteger length = 0;
    
    NSUInteger i = 0;
    while (YES)
    {
        char buffer[4];
        short bufferLength;
        for (bufferLength = 0; bufferLength < 4; i++)
        {
            if (characters[i] == '\0')
                break;
            if (isspace(characters[i]) || characters[i] == '=')
                continue;
            buffer[bufferLength] = decodingTable[(short)characters[i]];
            if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
            {
                free(bytes);
                return nil;
            }
        }
        
        if (bufferLength == 0)
            break;
        if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
        {
            free(bytes);
            return nil;
        }
        
        //  Decode the characters in the buffer to bytes.
        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (bufferLength > 2)
            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (bufferLength > 3)
            bytes[length++] = (buffer[2] << 6) | buffer[3];
    }
    
    realloc(bytes, length);
    return [NSData dataWithBytesNoCopy:bytes length:length];
}

- (void)xml2Json:(NSArray *)parms
{
    NSDictionary *_dictParas = [parms objectAtIndex:0];
    //参数字典_dictParas
    //自己的代码实现
    id<doIScriptEngine> _scritEngine = [parms objectAtIndex:1];

    NSString *_callbackName = [parms objectAtIndex:2];
    //回调函数名_callbackName
    doInvokeResult *_invokeResult = [[doInvokeResult alloc] init];
    
    NSString *xml = [doJsonHelper GetOneText:_dictParas :@"source" :@""];

    if (!xml || xml.length == 0) {
        [[doServiceContainer Instance].LogEngine WriteError:nil :@"解析内容不能为空"];
        return;
    }
    NSDictionary *_dict = [NSDictionary dictionary];

    NSDictionary *_result = [NSDictionary dictionary];
    doXMLReader *xmlReader = [doXMLReader new];
    _result = [xmlReader dictionaryForXMLString:xml error:nil];
    _dict = [_result objectForKey:@"result"];
    
    if (!_dict) {
        NSError *error = (NSError *)[_result objectForKey:@"error"];
        if (error) {
            [[doServiceContainer Instance].LogEngine WriteError:nil :[error localizedFailureReason]];
        }
        return;
    }
    
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:_dict options:NSJSONWritingPrettyPrinted error:nil];
    
    NSString *string = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    

    [_invokeResult SetResultText:string];
    [_scritEngine Callback:_callbackName :_invokeResult];
    
//    NSLog(@"string = %@",string);
}

@end
