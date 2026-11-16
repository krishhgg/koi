import { PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import { encodeLivePreviews, LIVE_PREVIEWS_MAX_BYTES, livePreviewsFit } from '@koi/shared';

// Publishes the labels allowed to wake the box, where whatever wakes it
// reads them: the SSM parameter the wake function reads on AWS, or a file on
// a plain host (file-live.ts). Skips the call when nothing changed.
export interface LiveList {
	publish(labels: string[]): Promise<void>;
	// Whether a list of these labels can be published. Deployer.up asks before
	// it accepts a new label and refuses the label with the reason given here,
	// so a list too long at publish means records changed on disk behind
	// koid's back.
	room(labels: string[]): Room;
}

export type Room = { ok: true } | { ok: false; reason: string };

// A standard SSM parameter holds 4 KB (LIVE_PREVIEWS_MAX_BYTES): about 60
// previews with the longest labels. The deployer's fake in tests uses this
// too, so the cap is tested where it is enforced.
export function ssmRoom(labels: string[]): Room {
	return livePreviewsFit(labels)
		? { ok: true }
		: {
				ok: false,
				reason: `it would pass the ${LIVE_PREVIEWS_MAX_BYTES} bytes its SSM parameter holds`,
			};
}

export function ssmLiveList(name: string, client: SSMClient): LiveList {
	let last: string | undefined;
	return {
		room: ssmRoom,
		async publish(labels) {
			const value = encodeLivePreviews(labels);
			if (value === last) return;
			if (!livePreviewsFit(labels)) {
				throw new Error(
					`${labels.length} live previews do not fit in the ${LIVE_PREVIEWS_MAX_BYTES} bytes of ${name}`,
				);
			}
			await client.send(
				new PutParameterCommand({ Name: name, Value: value, Type: 'String', Overwrite: true }),
			);
			last = value;
		},
	};
}
