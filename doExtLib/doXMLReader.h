//
//  doXMLReader.h
//  Do_Algorithm_SM
//
//  Created by wl on 16/9/7.
//  Copyright © 2016年 DoAlgorithm_MM. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface doXMLReader : NSObject
{
    NSMutableArray *dictionaryStack;
    NSMutableString *textInProgress;
    NSError *errorPointer;
}

- (NSDictionary *)dictionaryForXMLData:(NSData *)data error:(NSError **)errorPointer;
- (NSDictionary *)dictionaryForXMLString:(NSString *)string error:(NSError **)errorPointer;


@end
