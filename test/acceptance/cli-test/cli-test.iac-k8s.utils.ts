import { getWorkspaceJSON } from '../workspace-helper';
import * as _ from '@snyk/lodash';
import { mapIaCTestResult } from '../../../src/lib/snyk-test/iac-test-result';

const iacTestPrep = async (
  t,
  utils,
  params,
  severityThreshold,
  additionaLpropsForCli,
) => {
  utils.chdirWorkspaces();
  params.server.setNextResponse(
    getWorkspaceJSON(
      'iac-kubernetes',
      `test-iac-${severityThreshold}-result.json`,
    ),
  );

  try {
    await params.cli.test('iac-kubernetes', {
      file: 'multi-file.yaml',
      iac: true,
      ...additionaLpropsForCli,
    });
    t.fail('should have thrown');
  } catch (testableObject) {
    return testableObject;
  }
};

export const iacErrorTest = async (
  t,
  utils,
  params,
  testArg,
  expectedError,
) => {
  utils.chdirWorkspaces();

  try {
    await params.cli.test(testArg, {
      iac: true,
    });
    t.fail('should have failed');
  } catch (err) {
    t.pass('throws err');
    t.match(err.message, expectedError, 'shows err');
  }
};

export const iacTestJson = async (t, utils, params, severityThreshold) => {
  const testableObject = await iacTestPrep(
    t,
    utils,
    params,
    severityThreshold,
    { severityThreshold, json: true },
  );
  const req = params.server.popRequest();
  t.is(req.query.severityThreshold, severityThreshold);

  const results = JSON.parse(testableObject.message);
  const expectedResults = mapIaCTestResult(
    getWorkspaceJSON(
      'iac-kubernetes',
      `test-iac-${severityThreshold}-result.json`,
    ),
  );

  iacTestJsonAssertions(t, results, expectedResults);
};

export const iacTest = async (
  t,
  utils,
  params,
  severityThreshold,
  numOfIssues,
) => {
  const testableObject = await iacTestPrep(
    t,
    utils,
    params,
    severityThreshold,
    {},
  );
  const res = testableObject.message;
  t.match(
    res,
    `Tested iac-kubernetes for known issues, found ${numOfIssues} issues`,
    `${numOfIssues} issue`,
  );
  iacTestMetaAssertions(t, res);
};

export const iacTestMetaAssertions = (t, res) => {
  const meta = res.slice(res.indexOf('Organization:')).split('\n');
  t.match(meta[0], /Organization:\s+test-org/, 'organization displayed');
  t.match(meta[1], /Type:\s+Kubernetes/, 'Type displayed');
  t.match(meta[2], /Target file:\s+multi-file.yaml/, 'target file displayed');
  t.match(meta[3], /Project name:\s+iac-kubernetes/, 'project name displayed');
  t.match(meta[4], /Open source:\s+no/, 'open source displayed');
  t.match(meta[5], /Project path:\s+iac-kubernetes/, 'path displayed');
  t.notMatch(
    meta[5],
    /Local Snyk policy:\s+found/,
    'local policy not displayed',
  );
};

export const iacTestJsonAssertions = (
  t,
  results,
  expectedResults,
  foundIssues = true,
) => {
  t.deepEqual(results.org, 'test-org', 'org is ok');
  t.deepEqual(results.projectType, 'k8sconfig', 'projectType is ok');
  t.deepEqual(results.path, 'iac-kubernetes', 'path is ok');
  t.deepEqual(results.projectName, 'iac-kubernetes', 'projectName is ok');
  t.deepEqual(results.targetFile, 'multi-file.yaml', 'targetFile is ok');
  t.deepEqual(results.dependencyCount, 0, 'dependencyCount is 0');
  t.deepEqual(results.vulnerabilities, [], 'vulnerabilities is empty');
  t.equal(results.cloudConfigResults, undefined);
  if (foundIssues) {
    t.deepEqual(
      _.sortBy(results.infrastructureAsCodeIssues, 'id'),
      _.sortBy(expectedResults.infrastructureAsCodeIssues, 'id'),
      'issues are the same',
    );
  } else {
    t.deepEqual(results.infrastructureAsCodeIssues, []);
  }
};
