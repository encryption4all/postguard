# IRMAseal
IRMAseal is an Identity Based Encryption (IBE) service that can be used to encrypt messages for ones identity. IRMAseal uses [IRMA](https://irma.app), a privacy-friendly identity platform, to authenticate these identies. These identities are stored on the users phone in the IRMA app in the form of uniquely identifying attributes. These attributes can be freely disclosed by the user to any party, but only with explicit consent of the user.

## About this repository
This repository is the home of the core code for the IRMAseal service. Code belonging to IRMAseal clients for mailclient are not included in this repository and are still a work in progress.

## Relation to IRMA
IRMAseal is developed independently of IRMA, but has a heavy dependency on IRMA for the attestation of ones identity. IRMAseal however was thought up by the maintainers of IRMA (Privacy by Design Foundation).

## Funding
Development of IRMAseal is partially funded by the Next Generation Internet initiative (NGI0) and NLnet.
