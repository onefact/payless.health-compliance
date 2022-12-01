# Payless Health Blog Post on Hospital Price Transparency Compliance

This code is used to generate the analyses of hospital price transparency data, co-published on the DoltHub blog and the Payless Health Blog.

We recommend Visual Studio Code with the python and jupyter extensions. 

## Environment
To replicate this on a Mac:
External dependencies:
```
brew install dolt
```

To install anaconda:
```
brew install --cask anaconda
```

To load the environment:

```
conda env create -f environment.yml
```

Activate the environment:
```
conda activate payless.health
```

## To prepare the data

```
brew install dolt
dolt clone onefact/paylesshealth
cd paylesshealth/
dolt checkout 7jb3uru19oq5gd5tgbictbq407r9u11f -b checkpoint
dolt table export hospitals hospitals.csv
```

## License

This software is licensed as Apache 2.0 by the One Fact Foundation. The hospital chargemaster data is licensed as CC BY-SA 4.0 as described here: https://www.dolthub.com/repositories/onefact/paylesshealth/doc/main/LICENSE.md.
