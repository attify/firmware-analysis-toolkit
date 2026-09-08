void validatePermission() {}
void reportBadMessage() {}
void dispatchRemoteAction() {}
void dominatingValidationGuard() {}

void ValidateRemoteAction() {
  validatePermission();
  dispatchRemoteAction();
  reportBadMessage();
}

void PermissionCheckedMojoDispatch() {
  validatePermission();
  dispatchRemoteAction();
}

void GuardedPermissionDispatch() {
  dominatingValidationGuard();
  validatePermission();
  dispatchRemoteAction();
}
