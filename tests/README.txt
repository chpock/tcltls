Create Test Cases

1. Create test case *.csv file. You can use multiple files. Generally it's a good idea to group like functions in the same file.

2. Add test cases to *.csv files.
	Each test case is on a separate line. Each column defines the equivalent input the tcltest tool expects.

3. Define any common functions in common.tcl or in *.csv file.

4. To create the test cases script, execute make_test_files.tcl. This will use the *.csv files to create the *.test files.

Execute Test Suite

5. To run the test suite, execute the all.tcl file. The results will be output to the stdoutlog.txt file.
	On Windows you can also use the run_all_tests.bat file.

6. Review stdoutlog.txt for the count of test cases executed successfully and view details of those that failed.
