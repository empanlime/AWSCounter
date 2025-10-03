#!/usr/bin/env python3
"""
aws_asset_counter.py
---------------------

* **EC2 instances** (VMs not running containers)
* **ECS container instances** (VMs hosting containers)
* **ECS tasks** (managed containers, including Fargate tasks)
* **Lambda functions** (serverless functions)
* **S3 buckets** (cloud buckets)
* **RDS instances** (managed databases / PaaS)
* **DynamoDB tables** (DBaaS)
* **IAM users** (as a stand‑in for SaaS users)
* **ECR images** (container images in registries)

The script outputs a summary of asset counts for each category.  Categories
such as unmanaged assets (cloud attack surface) are not directly
discoverable via AWS APIs and therefore aren’t included.
"""

import sys
from collections import OrderedDict
from typing import Dict

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError as exc:
    sys.stderr.write(
        "boto3 is required to run this script. Install it with 'pip install boto3'\n"
    )
    raise


def list_regions(service: str) -> list:
    """Return a list of region names for the given service."""
    session = boto3.session.Session()
    return session.get_available_regions(service)


def count_ec2_instances() -> int:
    """Count EC2 instances across all regions (excluding terminated)."""
    total = 0
    regions = list_regions("ec2")
    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": [
                    "pending", "running", "stopping", "stopped"
                ]}]
            ):
                for reservation in page.get("Reservations", []):
                    total += len(reservation.get("Instances", []))
        except ClientError as e:
            # Skip regions where EC2 is not permitted
            sys.stderr.write(f"EC2 error in region {region}: {e}\n")
            continue
    return total


def count_ecs_container_instances() -> int:
    """Count ECS container instances (EC2 hosts running ECS tasks) across all regions."""
    total = 0
    regions = list_regions("ecs")
    for region in regions:
        ecs = boto3.client("ecs", region_name=region)
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                container_arns = ecs.list_container_instances(cluster=cluster).get(
                    "containerInstanceArns", []
                )
                total += len(container_arns)
        except ClientError as e:
            sys.stderr.write(f"ECS error in region {region}: {e}\n")
            continue
    return total


def count_ecs_tasks() -> int:
    """Count ECS tasks (Fargate/EC2 tasks) across all regions."""
    total = 0
    regions = list_regions("ecs")
    for region in regions:
        ecs = boto3.client("ecs", region_name=region)
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                task_arns = ecs.list_tasks(cluster=cluster).get("taskArns", [])
                total += len(task_arns)
        except ClientError as e:
            sys.stderr.write(f"ECS task error in region {region}: {e}\n")
            continue
    return total


def count_lambda_functions() -> int:
    """Count Lambda functions across all regions."""
    total = 0
    regions = list_regions("lambda")
    for region in regions:
        lam = boto3.client("lambda", region_name=region)
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                total += len(page.get("Functions", []))
        except ClientError as e:
            sys.stderr.write(f"Lambda error in region {region}: {e}\n")
            continue
    return total


def count_s3_buckets() -> int:
    """Count S3 buckets. S3 buckets are global, not regional."""
    s3 = boto3.client("s3")
    try:
        response = s3.list_buckets()
        return len(response.get("Buckets", []))
    except ClientError as e:
        sys.stderr.write(f"S3 error: {e}\n")
        return 0


def count_rds_instances() -> int:
    """Count RDS DB instances across all regions."""
    total = 0
    regions = list_regions("rds")
    for region in regions:
        rds = boto3.client("rds", region_name=region)
        try:
            dbs = rds.describe_db_instances().get("DBInstances", [])
            total += len(dbs)
        except ClientError as e:
            sys.stderr.write(f"RDS error in region {region}: {e}\n")
            continue
    return total


def count_dynamo_tables() -> int:
    """Count DynamoDB tables across all regions."""
    total = 0
    regions = list_regions("dynamodb")
    for region in regions:
        dynamo = boto3.client("dynamodb", region_name=region)
        try:
            paginator = dynamo.get_paginator("list_tables")
            for page in paginator.paginate():
                total += len(page.get("TableNames", []))
        except ClientError as e:
            sys.stderr.write(f"DynamoDB error in region {region}: {e}\n")
            continue
    return total


def count_iam_users() -> int:
    """Count IAM users in the account."""
    iam = boto3.client("iam")
    total = 0
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            total += len(page.get("Users", []))
    except ClientError as e:
        sys.stderr.write(f"IAM error: {e}\n")
    return total


def count_ecr_images() -> int:
    """Count container images across all ECR repositories and regions."""
    total = 0
    regions = list_regions("ecr")
    for region in regions:
        ecr = boto3.client("ecr", region_name=region)
        try:
            repos = ecr.describe_repositories().get("repositories", [])
            for repo in repos:
                images = ecr.list_images(repositoryName=repo["repositoryName"]).get(
                    "imageIds", []
                )
                total += len(images)
        except ClientError as e:
            sys.stderr.write(f"ECR error in region {region}: {e}\n")
            continue
    return total


def get_asset_counts() -> Dict[str, int]:
    """Gather counts for various asset types. Returns an ordered dict."""
    counts = OrderedDict()
    counts["ec2_instances"] = count_ec2_instances()
    counts["ecs_container_instances"] = count_ecs_container_instances()
    counts["ecs_tasks"] = count_ecs_tasks()
    counts["lambda_functions"] = count_lambda_functions()
    counts["s3_buckets"] = count_s3_buckets()
    counts["rds_instances"] = count_rds_instances()
    counts["dynamodb_tables"] = count_dynamo_tables()
    counts["iam_users"] = count_iam_users()
    counts["ecr_images"] = count_ecr_images()
    return counts


def main() -> None:
    counts = get_asset_counts()
    print("AWS Asset Counts:")
    for name, count in counts.items():
        print(f"- {name}: {count}")


if __name__ == "__main__":
    main()
