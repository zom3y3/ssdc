$(document).ready(function() {
  var ajax_url = "data/cache_data.php",
    ajax_type = "POST",
    ajax_data = JSON.stringify({
      "session": session_str,
      "type": "query"
  });
  $.ajax({
    url: ajax_url,
    type: ajax_type,
    data: ajax_data,
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    beforeSend: startLoading,
    success: startRunning,
    complete: endLoading,
    error: endLoading
  });
});
function startRunning(graph) {
  var width = $(window).width()/1;
  var height = $(window).height()/1;
  var simulation = createSimulation(width, height);
  addGraphToSimulation(simulation, graph);
  runSimulation(simulation);
  endLoading();
  var fileNameToTag = genFilenameToTag(graph);
  var neighbourChecker = genNeighbourChecker(graph);
  var color = d3.scaleOrdinal(d3.schemeCategory20);
  var svg = d3.select("svg").attr("width", width).attr("height", height);
  var g = svg.append("g").attr("class", "everything");
  var gLinks = g.append("g").attr("class", "links").selectAll("line").data(graph.links).enter()
  .append("line").attr("stroke-width", function(d) {
    return Math.sqrt(d.value)
  });
  var gNodes = g.append("g").attr("class", "nodes").selectAll("circle").data(graph.nodes).enter()
  .append("circle")
  .attr("r", function(d) {
    if (isClusterNode(d)) {
      return 15
    } else if (isSSDeepNode(d)) {
      return 10
    } else {
      return 5
    }
  }).attr("fill", function(d) {
    return color(d.group)
  });

  var gLabels = g.append("g")
    .attr("class", "label")
    .selectAll("text")
    .data(graph.nodes.filter(isClusterNode))
    .enter()
    .append("text")
    .attr("dy", 1)
    .text(getClusterLabel);
  var gLabels2 = g.append("g")
    .attr("class", "label2")
    .selectAll("text")
    .data(graph.nodes.filter(isFilenameNode))
    .enter()
    .append("text")
    .attr("dy", 1)
    .text(function (d) {
      return getFilenameLabel(d, fileNameToTag);
    });
  var divTooltip = d3.select("body").append("div")
    .attr("class", "tooltip")
    .style("opacity", 0);
  var zoom = d3.zoom().scaleExtent([0.2, 10]).on("zoom", function() {
    hideTooltip();
    g.attr("transform", d3.event.transform);
  });
  svg.call(zoom);
  svg.call(zoom.scaleTo, getInitZoomScale(graph, width, height));
  var drag = d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
  gNodes.call(drag);
  gNodes.on("mouseover", function(d) {
    showTooltip(d);
    highlight(d);
  });
  gNodes.on("mouseout", function() {
    hideTooltip();
    dehighlight();
  });
  gNodes.on("click", function(d) {
    console.log(d.id)
  });
  d3.select(window).on("keydown", keydown);
  function keydown() {
    if (d3.event.keyCode==32) {
      runSimulation(simulation);
      updateLayout();
    }
  }
  function applyLayout() {
    gLinks.attr("x1", function(d) {
      return d.source.x
    }).attr("y1", function(d) {
      return d.source.y
    }).attr("x2", function(d) {
      return d.target.x
    }).attr("y2", function(d) {
      return d.target.y
    });
    gNodes.attr("cx", function(d) {
      return d.x
    }).attr("cy", function(d) {
      return d.y
    });
    gLabels.attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
    gLabels2.attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
  }
  function updateLayout() {
    var dur = 1000;
    gLinks.transition().duration(dur)
    .attr("x1", function(d) {
      return d.source.x
    }).attr("y1", function(d) {
      return d.source.y
    }).attr("x2", function(d) {
      return d.target.x
    }).attr("y2", function(d) {
      return d.target.y
    });
    gNodes.transition().duration(dur)
    .attr("cx", function(d) {
      return d.x
    }).attr("cy", function(d) {
      return d.y
    });
    gLabels.transition().duration(dur)
    .attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
    gLabels2.transition().duration(dur)
    .attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
  }
  function applyDrag(node) {
    gLinks.filter(function(d) {
      return d.source === node;
    }).attr("x1", function(d) {
      return d.source.x
    }).attr("y1", function(d) {
      return d.source.y
    });
    gLinks.filter(function(d) {
      return d.target === node;
    }).attr("x2", function(d) {
      return d.target.x
    }).attr("y2", function(d) {
      return d.target.y
    });
    gNodes.filter(function(d) {
      return d === node;
    }).attr("cx", function(d) {
      return d.x
    }).attr("cy", function(d) {
      return d.y
    });
    gLabels.filter(function(d) {
      return d === node;
    }).attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
    gLabels2.filter(function(d) {
      return d === node;
    }).attr("x", function(d) {
      return d.x
    }).attr("y", function(d) {
      return d.y
    });
  }
  applyLayout();
  var isDragging = false;
  function dragstarted(d) {
    isDragging = true;
    hideTooltip();
  }
  function dragged(d) {
    d.x = d3.event.x;
    d.y = d3.event.y;
    applyDrag(d);
  }
  function dragended(d) {
    isDragging = false;
  }
  function showTooltip(node) {
    if (!isDragging) {
      divTooltip.style("opacity", .9);
      if (isFilenameNode(node)) {
      // if ((d.id + "").length == 64) {
        var tag = fileNameToTag[node.id];
        if (tag) {
          divTooltip.html("Filename: " + tag['filename'] + '<br>' + "MD5: " + tag['md5'] + '<br>' + "Tag: " + tag['tag'])
          .style("left", (d3.event.pageX) + "px")
          .style("top", (d3.event.pageY-50) + "px");
        }
      }else{
        divTooltip.html(node.id.replace('cluster_','Cluster ').replace('session_','session: '))
        .style("left", (d3.event.pageX) + "px")
        .style("top", (d3.event.pageY - 28) + "px");
      }
    }
  }
  function hideTooltip() {
    divTooltip.style("opacity", 0);
  }
  function highlight(node) {
    //Reduce the opacity of all but the neighbouring nodes
    gNodes.style("opacity", function(d) {
      return neighbourChecker(node, d) ? 1 : 0.1;
    });
    gLabels.style("opacity", function(d) {
      return neighbourChecker(node, d) ? 1 : 0.1;
    });
    gLabels2.style("opacity", function(d) {
      return neighbourChecker(node, d) ? 1 : 0.1;
    });
    gLinks.style("opacity", function(d) {
      return node.index == d.source.index || node.index == d.target.index ? 1 : 0.1;
    });
  }
  function dehighlight() {
    gNodes.style("opacity", 1);
    gLabels.style("opacity", 1);
    gLabels2.style("opacity", 1);
    gLinks.style("opacity", 1);
  }
}
function startLoading() {
  $("#loading").html("<img src='img/loading.gif'></img>");
}
function endLoading() {
  $("#loading").empty();
}
function createSimulation(width, height) {
  var simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(function(d) {
      return d.id
    }))
    .force("collide",d3.forceCollide( function(d){return d.r + 8; }) )
    .force("charge", d3.forceManyBody().strength(-90))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("y", d3.forceY(0))
    .force("x", d3.forceX(0))
    .stop();
  return simulation;
}
function addGraphToSimulation(simulation, graph) {
  simulation.nodes(graph.nodes);
  simulation.force("link").links(graph.links);
}
function runSimulation(simulation) {
  simulation.force("link").iterations(3);
  simulation.force("collide").iterations(0);
  var n1=100, alpha = 1;
  simulation.alpha(alpha);
  for (var i=0; i<n1; i++) {
    simulation.tick();
    // console.log(i);
  }
  simulation.force("link").iterations(1);
  simulation.force("collide").iterations(1);
  var n2 = 10, alphaDecay = Math.pow(0.05, 1/n2);
  for (var i=0; i<n2; i++) {
    alpha *= alphaDecay;
    simulation.alpha(alpha);
    simulation.tick();
  }
}
function genNeighbourChecker(graph) {
  var linkedByIndex = {};
  for (i = 0; i < graph.nodes.length; i++) {
    linkedByIndex[i + "," + i] = true;
  };
  graph.links.forEach(function(d) {
    linkedByIndex[d.source.index + "," + d.target.index] = true;
  });
  return function neighbourChecker(a, b) {
    return linkedByIndex[a.index + "," + b.index] || linkedByIndex[b.index + "," + a.index];
  }
}
function genFilenameToTag(graph) {
  var m = {};
  for(var i=0,l=graph.tags.length;i<l;i++){
    var tag = graph.tags[i];
    m[tag['filename']] = tag;
  }
  return m;
}
function isClusterNode(node) {
  return (node.id + "").indexOf("cluster") > -1;
}
function isSSDeepNode(node) {
  return (node.id + "").indexOf(":") > -1;
}
function isFilenameNode(node) {
  return !(isClusterNode(node) || isSSDeepNode(node));
}
function getClusterLabel(node) {
  return node.id.replace('cluster_','Cluster ');
}
function getFilenameLabel(node, fileNameToTag) {
  var tag = fileNameToTag[node.id]
  return tag ? tag.tag : null;
}
function getInitZoomScale(graph, width, height) {
  if (graph.nodes.length === 0) return 1;
  var minX = d3.min(graph.nodes.map(function (node) {return node.x})),
    maxX = d3.max(graph.nodes.map(function (node) {return node.x})),
    minY = d3.min(graph.nodes.map(function (node) {return node.y})),
    maxY = d3.max(graph.nodes.map(function (node) {return node.y})),
    layoutSize = Math.max(maxX - minX, maxY - minY),
    optimalSize = Math.min(width, height) * 0.9;
  if (layoutSize < optimalSize) return 1;
  return optimalSize / layoutSize;
}
