//
//  doXMLReader.m
//  Do_Algorithm_SM
//
//  Created by wl on 16/9/7.
//  Copyright © 2016年 DoAlgorithm_MM. All rights reserved.
//

#import "doXMLReader.h"

@interface doXMLReader ()<NSXMLParserDelegate>

- (NSDictionary *)objectWithData:(NSData *)data;

@end


@implementation doXMLReader
#pragma mark -
#pragma mark Public methods

- (instancetype)init
{
    self = [super init];
    if (self) {
        errorPointer = [NSError new];
    }
    return self;
}

- (NSDictionary *)dictionaryForXMLData:(NSData *)data error:(NSError **)error
{
    NSDictionary *rootDictionary = [self objectWithData:data];
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    [dict setObject:rootDictionary forKey:@"result"];
    [dict setObject:errorPointer forKey:@"error"];
    return dict;
}

- (NSDictionary *)dictionaryForXMLString:(NSString *)string error:(NSError **)error
{
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self dictionaryForXMLData:data error:error];
}

#pragma mark -
#pragma mark Parsing
- (NSDictionary *)objectWithData:(NSData *)data
{
    dictionaryStack = [[NSMutableArray alloc] init];
    textInProgress = [[NSMutableString alloc] init];
    
    [dictionaryStack addObject:[NSMutableDictionary dictionary]];

    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];
    parser.delegate = self;
    BOOL success = [parser parse];

    if (success)
    {
        NSDictionary *resultDict = [dictionaryStack objectAtIndex:0];
        return resultDict;
    }
    
    return nil;
}

#pragma mark -
#pragma mark NSXMLParserDelegate methods

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary *)attributeDict
{
    NSMutableDictionary *parentDict = [dictionaryStack lastObject];

    NSMutableDictionary *childDict = [NSMutableDictionary dictionary];
    [childDict addEntriesFromDictionary:attributeDict];

    id existingValue = [parentDict objectForKey:elementName];
    if (existingValue)
    {
        NSMutableArray *array = nil;
        if ([existingValue isKindOfClass:[NSMutableArray class]])
        {
            array = (NSMutableArray *) existingValue;
        }
        else
        {
            array = [NSMutableArray array];
            [array addObject:existingValue];

            [parentDict setObject:array forKey:elementName];
        }

        [array addObject:childDict];
    }
    else
    {
        [parentDict setObject:childDict forKey:elementName];
    }

    [dictionaryStack addObject:childDict];
}

- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName
{
    NSInteger count = [dictionaryStack count];
    NSMutableDictionary *dictInProgress = [dictionaryStack objectAtIndex:(count-2)];

    if ([textInProgress length] > 0)
    {
        [dictInProgress setObject:textInProgress forKey:elementName];
        textInProgress = [[NSMutableString alloc] init];
    }
    
    [dictionaryStack removeLastObject];
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string
{
    [textInProgress appendString:string];
}

- (void)parser:(NSXMLParser *)parser parseErrorOccurred:(NSError *)parseError
{
    errorPointer = parseError;
}

@end
