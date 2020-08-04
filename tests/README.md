# Install requirements

On Linux you need: `sudo apt install swig libpcsclite-dev`

Install requirements: `pip3 install -r requirements.txt`

# Running tests

First make sure you've built applet you are testing (or maybe all of them).

To test in a simulator run:

```
python3 run_tests.py
```

Or a specific test:

```
python3 tests/test_teapot.py
```

To test on the real card first upload the applet to the card, and then run the same commands with `TEST_MODE=card`, for example:

```
TEST_MODE=card python3 tests/test_teapot.py
```
