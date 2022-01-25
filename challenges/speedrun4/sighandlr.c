#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
        struct sigaction sa = { 0 };

        sa.sa_handler = SIG_IGN;
        sigaction(SIGALRM, &sa, 0);

	execvp("./speedrun-004",0);        
	return 1;
}
