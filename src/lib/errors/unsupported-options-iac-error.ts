export function SupportLocalFileOnlyIacError() {
  const errorMsg =
    'iac test option currently supports only a single local file';
  return new Error(errorMsg);
}

export function UnsupportedOptionFileIacError(path: string) {
  const errorMsg =
    `Not a recognised option, did you mean "snyk iac test ${path}"? ` +
    'Check other options by running snyk iac --help';
  return new Error(errorMsg);
}
