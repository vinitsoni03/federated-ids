"""Flower ClientApp: one SuperNode = one client holding partition `partition-id`.

SuperNode node-config keys: partition-id, num-partitions, data-dir (folder with client_<i>.npz)."""
from __future__ import annotations

from flwr.app import ArrayRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp

from federated_ids.models.mlp import MLP, class_weights, resolve_device, train_epochs

from fids_flower.common import CLASS_WEIGHTING, MODEL, client_data, manifest

app = ClientApp()


# Flower calls this every round with the current global model inside msg
@app.train()
def train(msg: Message, context: Context):
    # run_config = same for everyone (lr, epochs...), node_config = this machine only (which partition, where the data is)
    rc, nc = context.run_config, context.node_config
    pid, data_dir = int(nc["partition-id"]), str(nc["data-dir"])
    man = manifest(data_dir)
    # guard against starting a client with the wrong data folder
    if int(nc["num-partitions"]) != int(man["n_clients"]):
        raise ValueError(f"num-partitions={nc['num-partitions']} but data in {data_dir} has {man['n_clients']} clients")
    X, y = client_data(data_dir, pid)
    K = len(man["class_names"])
    model = MLP(X.shape[1], K, MODEL["hidden"], MODEL["dropout"])
    # start from the global weights the server just sent
    model.load_state_dict(msg.content["arrays"].to_torch_state_dict())
    model.to(resolve_device(str(rc["device"])))
    rnd = int(msg.content["config"]["server-round"])
    # same per-client/per-round seed formula as the in-process simulator
    loss = train_epochs(model, X, y, class_weights(y, K, CLASS_WEIGHTING), int(rc["local-epochs"]),
                        float(rc["learning-rate"]), int(rc["batch-size"]),
                        int(man["seed"]) * 100000 + rnd * 100 + pid)
    # send back only the new weights and how many samples we trained on (FedAvg weights by that number)
    model.to("cpu")
    content = RecordDict({"arrays": ArrayRecord(model.state_dict()),
                          "metrics": MetricRecord({"train_loss": float(loss), "num-examples": int(len(y))})})
    return Message(content=content, reply_to=msg)
