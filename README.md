mod_randpad
===========

An nginx module that adds a random amount of random padding.

Why?
----
Unless you've been living under a rock for a while, you've had heard of the BREACH attack against SSL. It's detailed here: http://breachattack.com/
Now if you've read the paper, I know what you're thinking - the original researchers suggested random padding wasn't a great mitigation. Here's what they said:
`While this measure does make the attack take longer, it does so only slightly.
The countermeasure requires the attacker to issue more requests, and measure the
sizes of more responses, but not enough to make the attack infeasible.`

Whilst we're on topic of mitigations, here's what they said about another one - rate limiting SSL:
`By monitoring the volume of traffic per user, and potentially eventually throttling users, the attack can at least be slowed down signicantly.`

So this is where we ask, what would make a useful mitigation, in the form of rate limiting SSL, even more effecient, if not adding a few zeroes to the number of requests an attacker needs to make?

Installation
------------
You will need to obtain the nginx source and link against it.

 1. Clone the git repo.
    `git clone  git://github.com/technion/mod_randpad.git`

 2. Add the module to the build configuration by adding
    `--add-module=/path/to/nginx-http-randpad-filter`

 3. Build the nginx binary.
 
 4. Install the nginx binary.
 
 5. Configure contexts where randpad filter is enabled.

 6. Done.

Configuration Example
---------------------

    location / {
        randpad "SECRET STRING";
        index index.html;
    }

Technical Notes
---------------

"Random" in this case is defined as SHA512(time(in usec) || secret). It is not completely crytographically secure - but felt appropriate for this scenario.

The final byte of the SHA512 is cast to an unsigned int, and used as an index to determine how much of the message digest will actually be sent to the footer.
