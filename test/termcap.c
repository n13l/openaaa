#include <stdio.h>
#include <stdlib.h>
#include <termcap.h>
#include <error.h>

static char termbuf[2048];

int main(void)
{
    char *termtype = getenv("TERM");

    if (tgetent(termbuf, termtype) < 0) {
        error(EXIT_FAILURE, 0, "Could not access the termcap data base.\n");
    }

    int lines = tgetnum("li");
    int columns = tgetnum("co");
    printf("lines = %d; columns = %d.\n", lines, columns);
    return 0;
}
