#!/bin/bash

while true; do
  (./panu_demo_fuzz) & pid=$!;
  sleep 10 && kill -9 $pid;
done;
