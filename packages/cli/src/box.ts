// The box as the CLI saw it before there were transports. The AWS code lives
// in transports/aws.ts and the interface in transport.ts; this module keeps
// the old names so that up.ts, main.ts and their tests compile unchanged.
export {
	type Box,
	BoxUnavailableError,
	type CtlResult,
	ctlErrorText,
} from './transport.ts';
export {
	awsTransport as awsBox,
	type Clients,
	clients,
	ctlCommand,
	resolveSettings,
	type Settings,
} from './transports/aws.ts';
