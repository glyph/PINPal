# PINPal

A tool for helping you memorize random passwords.

## The Problem

Most of the time, we should store our passwords in password managers and not memorize them.

But there are a small number of passwords that you really need to have committed to memory:

- first and foremost, of course, the master password for your password manager
- the PIN code for your bank
- the unlock code for your mobile devices
- the password to the email account where the unlock codes

All of these codes should be rotated at least *somewhat* regularly, but doing
the work of re-memorizing these is super annoying and often we just don't
bother.

## The Solution

Rather than write down a password and rely on the process of needing to
actually unlock your devices, PINPal provides a spaced-repetition prompt to try
to help you remember them as you're working on a computer.

### Security

Since PINPal's job is to help you manage your most sensitive secrets, it
behooves it to treat its data very carefully.

Currently PINPal stores all secrets using the [Python `keyring`
module](https://keyring.readthedocs.io/en/latest/), and gradually forgets the
password as you make progress in memorizing it.

### Usage

To start memorizing a new secret,

```console
$ pinpal new
```

and you'll be prompted to label the new secret.

To check up on your secrets and get prompted to recite them, simply run

```console
$ pinpal
```

You will want to add

```sh
pinpal check
```

to something that is run frequently. I have it in my shell prompt.  This will
tell you when you need to run `pinpal`.
