# reporter

A script to set as your cronjob.


Every Wednesday at 5 A.M (once in a week):

0 5 * * 3 cd ~/tools/reporter/ ; sh reporter.sh

Everyday at 12 A.M:


0 0 * * * cd ~/tools/reporter/ ; sh reporter.sh
