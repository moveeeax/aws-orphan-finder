"""Shared AWS call helpers: error conversion, pagination, CloudWatch sums.

Every check module goes through these so a failed or truncated call is
handled the same way everywhere: it raises CheckFailed, and the caller reports
the check as skipped instead of rendering a partial answer.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:  # botocore ships with boto3, which is a hard dependency
    from botocore.exceptions import BotoCoreError, ClientError

    _AWS_ERRORS: Tuple[type, ...] = (BotoCoreError, ClientError)
except ImportError:  # pragma: no cover - only if botocore is unavailable
    _AWS_ERRORS = ()

# CloudWatch period used for traffic sums. One datapoint per day keeps a
# 14-day lookback at 14 datapoints, far below GetMetricStatistics' limit of
# 1,440 datapoints per call, and 86400 is a multiple of 3600 as CloudWatch
# requires for windows that start more than 63 days ago.
_METRIC_PERIOD_SECONDS = 86400


class CheckFailed(Exception):
    """A check could not be completed, so it must report nothing at all.

    Reporting an empty or partial result for a failed check is precisely how a
    false positive is manufactured: an AccessDenied on DescribeImages would
    otherwise make every AMI-backed snapshot look unreferenced, and the tool
    would recommend deleting the backing store of live machine images.
    """

    def __init__(self, operation: str, code: str, message: str) -> None:
        super().__init__(f"{operation}: {code}: {message}")
        self.operation = operation
        self.code = code
        self.message = message


def _error_parts(exc: BaseException) -> Tuple[str, str]:
    """Pull (code, message) out of a botocore exception as best we can."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error") or {}
        if isinstance(err, dict) and err.get("Code"):
            return str(err["Code"]), str(err.get("Message") or exc)
    return exc.__class__.__name__, str(exc)


def call(fn: Callable[..., Any], operation: str, **kwargs: Any) -> Any:
    """Invoke one AWS call, converting any AWS-side failure into CheckFailed.

    Throttling (RequestLimitExceeded) is retried inside botocore via the client
    config; if it still surfaces here the check is abandoned rather than being
    reported as an empty result.
    """
    try:
        return fn(**kwargs)
    except _AWS_ERRORS as exc:  # type: ignore[misc]
        code, message = _error_parts(exc)
        raise CheckFailed(operation, code, message) from exc


def _paginate_with(
    fn: Callable[..., Dict[str, Any]],
    key: str,
    operation: str,
    request_token: str,
    response_token: str,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    token: Optional[str] = None
    seen_tokens: Set[str] = set()
    while True:
        params = dict(kwargs)
        if token:
            params[request_token] = token
        resp = call(fn, operation, **params)
        items.extend(resp.get(key, []) or [])
        token = resp.get(response_token)
        if not token:
            break
        if token in seen_tokens:
            # A server repeating a token would otherwise spin forever.
            raise CheckFailed(operation, "PaginationLoop", f"{response_token} repeated by the API")
        seen_tokens.add(token)
    return items


def paginate(
    fn: Callable[..., Dict[str, Any]], key: str, operation: str, **kwargs: Any
) -> List[Dict[str, Any]]:
    """Follow EC2-style NextToken pagination for a describe_* call, collecting `key`.

    Every page must succeed. A failure part-way through raises rather than
    returning the pages gathered so far -- a truncated listing of *attachments*
    is what turns an in-use resource into a reported orphan.
    """
    return _paginate_with(fn, key, operation, "NextToken", "NextToken", **kwargs)


def paginate_marker(
    fn: Callable[..., Dict[str, Any]], key: str, operation: str, **kwargs: Any
) -> List[Dict[str, Any]]:
    """Same contract as `paginate`, for the ELB APIs (Marker / NextMarker)."""
    return _paginate_with(fn, key, operation, "Marker", "NextMarker", **kwargs)


def metric_sum(
    cloudwatch: Any,
    namespace: str,
    metric: str,
    dimensions: List[Dict[str, str]],
    now: datetime,
    lookback_days: int,
) -> Optional[float]:
    """Sum of `metric` over the last `lookback_days`, or None with no datapoints.

    None is not zero. Several ELB metrics are only published while traffic
    flows, but an empty answer is also what a wrong dimension or a metric that
    was never emitted looks like, so callers must treat None as "unknown".
    """
    resp = call(
        cloudwatch.get_metric_statistics,
        "GetMetricStatistics",
        Namespace=namespace,
        MetricName=metric,
        Dimensions=dimensions,
        StartTime=now - timedelta(days=lookback_days),
        EndTime=now,
        Period=_METRIC_PERIOD_SECONDS,
        Statistics=["Sum"],
    )
    datapoints = resp.get("Datapoints") or []
    if not datapoints:
        return None
    return float(sum(dp.get("Sum", 0.0) or 0.0 for dp in datapoints))


def name_tag(tags: Optional[List[Dict[str, str]]]) -> Optional[str]:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None


def as_datetime(value: Any) -> Optional[datetime]:
    """botocore returns datetimes for most timestamps but ISO strings for a few
    (Image.CreationDate, Image.LastLaunchedTime). Normalise both to aware UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def age_days(created: Any, now: datetime) -> Optional[int]:
    created_dt = as_datetime(created)
    if created_dt is None:
        return None
    return int((now - created_dt).total_seconds() // 86400)
