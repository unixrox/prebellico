# prebellico
Passive internal reconnaissance tool

Prebellico in its simplest form is a 100% passive network reconnissiance tool designed to gather as much information about the target environment without transmission. Execution is simple. Simply call prebellico with python as a root user and the information it gathers will be dumped to the screen. It is recommended that this us run upon bootup in something like gnu screen with a long scrollback buffer.

Soon prebellico will start to track the time between intelligence updates, and if so desired, work to move into a semi-passive mode after a user defined period of lack of intelligence, or after a specific period, leveraging the information it has obtained to further enumerate resources within the environment.

Prebellico also has the ability to understand what is permitted within the environment from network egress point, and if so told to do so, will establish a C2 connection using observed egress patters to report back to a listener the information it knows about a network.
