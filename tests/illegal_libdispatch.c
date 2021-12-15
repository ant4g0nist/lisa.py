
#include <dispatch/dispatch.h>

int main(int argc, char* argv[])
{
	dispatch_source_t theTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_queue_create("timer queue",NULL));
    	
	dispatch_source_set_timer(theTimer, dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC) , NSEC_PER_SEC, 0);

	dispatch_resume(theTimer);
	dispatch_resume(theTimer);

	dispatch_main();
	
	return 0;
}
