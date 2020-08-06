import { CustomError } from './custom-error';

export function UnsupportedLocalFolderIacError() {
  const errorMsg = 'iac test option currently support a single local file only';
  return genericUnsupportedOptionIacError(errorMsg);
}

export function UnsupportedOptionFileIacError(path: string) {
  const errorMsg =
    `Not a recognised option, did you mean "snyk iac test ${path}"? ` +
    'Check other options by running snyk iac --help';
  return genericUnsupportedOptionIacError(errorMsg);
}

function genericUnsupportedOptionIacError(errorMsg: string) {
  const error = new CustomError(errorMsg);
  error.code = 422;
  error.userMessage = errorMsg;
  return error;
}
