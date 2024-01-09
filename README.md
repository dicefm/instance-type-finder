# Spot Instance Finder

This is a script which parses the 3rd party [`spotinfo`](https://github.com/alexei-led/spotinfo),
as well as AWS data from the `describe instance-types` API.

It then produces a table, CSV output or raw JSON to help you work out what instance types to
specify when setting up an autoscaling group.

By default, the hardware architecture `x86_64` is selected, and the hypervisor `nitro` is also
selected. Instances which are not eligable for spot are hidden, as are instances which don't have
interruption data (from `spotinfo`). There is also a minimum spot interruption threshold of 10%.

To see how to adjust these values, run `./spot-instances-review.py --help`.

## Installation

You are recommended to use a virtual environment, so first run
`virtualenv .venv && source .venv/bin/activate`. On subsequent runs, you will only need to run
`source .venv/bin/activate` before running the script.

This script uses Python3 and a couple of python libraries, so ensure you have python3 and pip
installed, and then run `pip install -r requirements.txt`.

## Running

Running `./spot-instances-finder.py` will use the following criteria:

```text
INFO:root:Search criteria:
INFO:root:Memory      : >0.1 <10000.0
INFO:root:CPU         : >0.1 <10000.0
INFO:root:architecture: x86_64
INFO:root:hypervisor  : nitro
INFO:root:interruption: <10
```

You can use additional flags to change these values. As a shorthand, you can also use the flag
`./spot-instances-finder.py --like t3.2xlarge` which will show you all the options which are
directly comparable to the `t3.2xlarge` instance size (for example).

If you run `./spot-instances-finder.py --order-by-price` this will order the results by the
spot price. Run it `./spot-instances-finder.py --order-by-interruption` and it will return the
results by the risk of interruption.
