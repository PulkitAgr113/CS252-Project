This project was done by [Pulkit Agarwal](https://github.com/PulkitAgr113) and [Jash Kabra](https://github.com/JashKabra) as part of Computer Networks Lab (CS252).


Syntax for running: `./run.sh <path-to-testcase> <number-of-clients> <phase>`

For eg: `./run.sh ./tc18 18 3` will store your output for phase 3 in a folder called output, while actually downloading the required files in the testcase folder itself.

[tc18](tc18) is a sample test case with 18 clients, with the folder [sol18](sol18) containing files ans_x_y, which is the expected output of client x on phase y.

To check the correctness of the code, run the following code: `./diff.sh <path-to-solutions> <number-of-clients> <phase>`

For eg: `./diff.sh ./sol18 18 3` will generate files representing the differences between the expected and the obtained output in the diffs folder.
