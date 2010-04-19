#!/bin/bash

ps aux | grep controller | cut -c10-14 | xargs kill -9
