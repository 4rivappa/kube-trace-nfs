#!/bin/bash

apt-get update
apt-get install software-properties-common

add-apt-repository ppa:deadsnakes/ppa

apt-get update

apt-get install python3.9
apt-get install python3-pip
