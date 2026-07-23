# Registering a Name

This guide explains how to claim your own `.kin` name on the Kinetic network.

## How it Works

Kinetic names are completely free, but they require a computational investment. To register a name, your computer must perform a Verifiable Delay Function (VDF). Think of it as cryptographic proof that your computer spent a specific amount of time working on the name.

The shorter the name, the longer it takes to compute. This prevents bots from instantly claiming all the short, desirable names.

| Name Length | Approximate Time Required |
| :--- | :--- |
| 8+ characters | ~2 hours |
| 6 characters | ~12 hours |
| 4 characters | ~15 days |
| 2 characters | ~5 months |

## Rules for Names

Names must follow strict formatting rules:
- Must use only lowercase letters (`a-z`), numbers (`0-9`), and hyphens (`-`).
- No spaces or special characters.
- Must end with `.kin`.
- Must not be reserved (e.g., `localhost.kin`, `test.kin`).

**Valid:** `alice.kin`, `my-project.kin`, `hello123.kin`
**Invalid:** `Alice.kin` (uppercase), `my name.kin` (space), `hello_world.kin` (underscore)

## Step 1: Start the Registration

Make sure your `kinetic daemon` is running in the background. Then, in a new terminal, run:

```bash
kinetic name register myname.kin
```

*(Replace `myname.kin` with your desired name)*

**What happens next?**
1. The daemon fetches a random challenge from the internet.
2. It starts the heavy VDF computation. Your CPU usage will increase, and the daemon will work silently in the background.
3. Once the time is up, the daemon will automatically secure the name for you.

::: tip
You can check on the progress at any time by running:
`kinetic name info myname.kin`
:::

## Step 2: Configure Your DNS Records

When the registration finishes, Kinetic creates a zone file on your computer. This file tells the network where to route your name.

You must edit this file to add your IP addresses or websites. See the [DNS Records Guide](/users/dns-records) for instructions on how to edit this file.

## Step 3: Publish Your Name

Once your name is registered and you have edited your zone file, you must publish it to the global network so everyone else can see it.

```bash
kinetic name publish myname.kin
```

## Step 4: Verify

You can verify that your name is live and resolving correctly by using standard command-line tools:

```bash
dig @127.0.0.1 myname.kin A
```

If it returns the IP address you set in your zone file, congratulations! Your `.kin` name is officially live on the network.

## What if someone else takes it first?

Kinetic enforces a strict first-to-finish rule. Only one VDF task per name is permitted concurrently on your machine. If someone else finishes the VDF computation and publishes the name to the network before you do, your attempt will be rejected by the network.
