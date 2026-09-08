void mapAsync() {}
void unmapBuffer() {}
void destroyBuffer() {}
void submitQueue() {}
void deviceLostCallback() {}
void explicitStateGuard() {}

void MapDestroySequence() {
  mapAsync();
  submitQueue();
  destroyBuffer();
}

void DeviceLostAsyncSequence() {
  submitQueue();
  deviceLostCallback();
  unmapBuffer();
}

void GuardedDeviceLossHandler() {
  explicitStateGuard();
  submitQueue();
  destroyBuffer();
}
