// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
//

package provisioner

import (
	"fmt"
	"strings"

	"github.com/mattermost/mattermost-cloud/internal/tools/aws"
	"github.com/mattermost/mattermost-cloud/internal/tools/kops"
	"github.com/mattermost/mattermost-cloud/model"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type nginx struct {
	awsClient      aws.AWS
	provisioner    *KopsProvisioner
	kops           *kops.Cmd
	logger         log.FieldLogger
	cluster        *model.Cluster
	desiredVersion string
	actualVersion  string
}

func newNginxHandle(desiredVersion string, cluster *model.Cluster, provisioner *KopsProvisioner, awsClient aws.AWS, kops *kops.Cmd, logger log.FieldLogger) (*nginx, error) {
	if logger == nil {
		return nil, errors.New("cannot instantiate NGINX handle with nil logger")
	}

	if cluster == nil {
		return nil, errors.New("cannot create a connection to Nginx if the cluster provided is nil")
	}

	if provisioner == nil {
		return nil, errors.New("cannot create a connection to Nginx if the provisioner provided is nil")
	}

	if awsClient == nil {
		return nil, errors.New("cannot create a connection to Nginx if the awsClient provided is nil")
	}

	if kops == nil {
		return nil, errors.New("cannot create a connection to Nginx if the Kops command provided is nil")
	}

	return &nginx{
		awsClient:      awsClient,
		provisioner:    provisioner,
		kops:           kops,
		cluster:        cluster,
		logger:         logger.WithField("cluster-utility", model.NginxCanonicalName),
		desiredVersion: desiredVersion,
	}, nil

}

func (n *nginx) updateVersion(h *helmDeployment) error {
	actualVersion, err := h.Version()
	if err != nil {
		return err
	}

	n.actualVersion = actualVersion
	return nil
}

func (n *nginx) CreateOrUpgrade() error {
	h, err := n.NewHelmDeployment()
	if err != nil {
		return errors.Wrap(err, "failed to generate nginx helm deployment")
	}

	err = h.Update()
	if err != nil {
		return err
	}

	err = n.updateVersion(h)
	return err
}

func (n *nginx) DesiredVersion() string {
	return n.desiredVersion
}

func (n *nginx) ActualVersion() string {
	return strings.TrimPrefix(n.actualVersion, "ingress-nginx-")
}

func (n *nginx) Destroy() error {
	return nil
}

func (n *nginx) Migrate() error {
	return nil
}

func (n *nginx) NewHelmDeployment() (*helmDeployment, error) {
	awsACMCert, err := n.awsClient.GetCertificateSummaryByTag(aws.DefaultInstallCertificatesTagKey, aws.DefaultInstallCertificatesTagValue, n.logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrive the AWS ACM")
	}

	clusterResources, err := n.awsClient.GetVpcResources(n.cluster.ID, n.logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrive the VPC information")
	}

	return &helmDeployment{
		chartDeploymentName: "nginx",
		chartName:           "ingress-nginx/ingress-nginx",
		namespace:           "nginx",
		valuesPath:          "helm-charts/nginx_values.yaml",
		setArgument:         fmt.Sprintf("controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-cert=%s,controller.config.proxy-real-ip-cidr=%s", *awsACMCert.CertificateArn, clusterResources.VpcCIDR),
		desiredVersion:      n.desiredVersion,

		cluster:         n.cluster,
		kopsProvisioner: n.provisioner,
		kops:            n.kops,
		logger:          n.logger,
	}, nil
}

func (n *nginx) Name() string {
	return model.NginxCanonicalName
}
