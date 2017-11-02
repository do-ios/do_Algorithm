//
//  do_Algorithm_App.m
//  DoExt_SM
//
//  Created by @userName on @time.
//  Copyright (c) 2015年 DoExt. All rights reserved.
//

#import "do_Algorithm_App.h"
static do_Algorithm_App* instance;
@implementation do_Algorithm_App
@synthesize OpenURLScheme;
+(id) Instance
{
    if(instance==nil)
        instance = [[do_Algorithm_App alloc]init];
    return instance;
}
@end
