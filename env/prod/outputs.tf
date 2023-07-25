#output "efs" {
#  value = module.efs.arn
#}

output "role_cluster" {
  value = module.eks_cluster.cluster_iam_role_arn
}

#output "role_ec2" {
#  value = module.ec2_bastion.ec2_role_arn
#}

output "role_eks_unique_id" {
  value = module.eks_cluster.cluster_iam_role_unique_id
}
