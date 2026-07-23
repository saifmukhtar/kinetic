# Renewing a Name

Kinetic domains do not cost money to renew, but they do require proof that the owner is still active. 

## How Ownership Works

As long as your Kinetic daemon is running, it periodically broadcasts a "heartbeat" signature to the network. This heartbeat proves that you are alive and actively claiming your name. 

Because this happens automatically in the background, under normal circumstances, **you do not need to manually renew your names.**

## The Grace Period

If you turn off your computer or the daemon stops running, the network will no longer receive your heartbeat. If you are offline for an extended period (typically months), your name enters a **Grace Period**.

During the grace period, your name is still protected, but its defense is degraded. The longer you remain offline, the easier it becomes for an attacker to claim your name by performing a harder VDF computation to overtake it.

## When to Renew Manually

If you have been offline for many months and your name is deep in the grace period, you should manually renew it to restore its full protection.

To renew a name, run:

```bash
kinetic name renew myname.kin
```

### What happens during renewal?

Renewing a name requires the exact same VDF computation as registering it for the first time. For example, if you are renewing an 8-character name, the daemon will run for about 2 hours at full CPU load. 

Once the VDF computation completes, the daemon broadcasts the new proof to the network, and your name is fully secured again.

## What if my name was stolen?

If you were offline for so long that an attacker successfully computed a harder VDF and stole your name, the name is unfortunately gone. Kinetic is a decentralized protocol, and there is no central authority that can reverse the takeover. If you believe there is a protocol issue, reach out to the community.
