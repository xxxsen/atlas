package matcher

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// BuildExpressionMatcher compiles a logical expression composed of registered matchers.
// Supported operators: &&, ||, ! plus their textual counterparts (and, or, not).
func BuildExpressionMatcher(expr string, registry map[string]IDNSMatcher) (IDNSMatcher, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty matcher expression")
	}
	tokens, err := tokenizeExpression(expr)
	if err != nil {
		return nil, err
	}
	root, err := parseExpression(tokens, registry)
	if err != nil {
		return nil, err
	}
	return &expressionMatcher{
		raw:  expr,
		root: root,
	}, nil
}

type tokenType int

const (
	tokenIdentifier tokenType = iota
	tokenAnd
	tokenOr
	tokenNot
	tokenLParen
	tokenRParen
)

type token struct {
	typ   tokenType
	value string
}

func tokenizeExpression(expr string) ([]token, error) {
	if expr == "" {
		return nil, nil
	}
	normalised := strings.NewReplacer(
		"&&", " && ",
		"||", " || ",
		"(", " ( ",
		")", " ) ",
		"!", " ! ",
	).Replace(expr)
	fields := strings.Fields(normalised)
	tokens := make([]token, 0, len(fields))
	for _, part := range fields {
		switch strings.ToLower(part) {
		case "&&", "and":
			tokens = append(tokens, token{typ: tokenAnd})
		case "||", "or":
			tokens = append(tokens, token{typ: tokenOr})
		case "!", "not":
			tokens = append(tokens, token{typ: tokenNot})
		case "(":
			tokens = append(tokens, token{typ: tokenLParen})
		case ")":
			tokens = append(tokens, token{typ: tokenRParen})
		default:
			tokens = append(tokens, token{typ: tokenIdentifier, value: part})
		}
	}
	return tokens, nil
}

type exprNode interface {
	eval(ctx context.Context, req *dns.Msg) (bool, error)
}

type expressionMatcher struct {
	raw  string
	root exprNode
}

func (e *expressionMatcher) Name() string {
	return e.raw
}

func (e *expressionMatcher) Type() string {
	return "expression"
}

func (e *expressionMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	return e.root.eval(ctx, req)
}

type matcherNode struct {
	matcher IDNSMatcher
}

func (m matcherNode) eval(ctx context.Context, req *dns.Msg) (bool, error) {
	return m.matcher.Match(ctx, req)
}

type notNode struct {
	child exprNode
}

func (n notNode) eval(ctx context.Context, req *dns.Msg) (bool, error) {
	ok, err := n.child.eval(ctx, req)
	if err != nil {
		return false, err
	}
	return !ok, nil
}

type binaryOp int

const (
	opAnd binaryOp = iota
	opOr
)

type binaryNode struct {
	op    binaryOp
	left  exprNode
	right exprNode
}

func (b binaryNode) eval(ctx context.Context, req *dns.Msg) (bool, error) {
	switch b.op {
	case opAnd:
		leftOK, err := b.left.eval(ctx, req)
		if err != nil {
			return false, err
		}
		if !leftOK {
			return false, nil
		}
		return b.right.eval(ctx, req)
	case opOr:
		leftOK, err := b.left.eval(ctx, req)
		if err != nil {
			return false, err
		}
		if leftOK {
			return true, nil
		}
		return b.right.eval(ctx, req)
	default:
		return false, fmt.Errorf("unsupported binary operator")
	}
}

func parseExpression(tokens []token, registry map[string]IDNSMatcher) (exprNode, error) {
	rpn, err := shuntingYard(tokens)
	if err != nil {
		return nil, err
	}
	stack := make([]exprNode, 0, len(rpn))
	for _, tk := range rpn {
		switch tk.typ {
		case tokenIdentifier:
			mt, ok := registry[tk.value]
			if !ok {
				return nil, fmt.Errorf("matcher %s not found", tk.value)
			}
			stack = append(stack, matcherNode{matcher: mt})
		case tokenNot:
			if len(stack) < 1 {
				return nil, fmt.Errorf("invalid expression: missing operand for NOT")
			}
			operand := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			stack = append(stack, notNode{child: operand})
		case tokenAnd, tokenOr:
			if len(stack) < 2 {
				return nil, fmt.Errorf("invalid expression: missing operands for binary operator")
			}
			right := stack[len(stack)-1]
			left := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			var op binaryOp
			if tk.typ == tokenAnd {
				op = opAnd
			} else {
				op = opOr
			}
			stack = append(stack, binaryNode{op: op, left: left, right: right})
		default:
			return nil, fmt.Errorf("unexpected token in rpn")
		}
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("invalid expression: unresolved operands remain")
	}
	return stack[0], nil
}

func shuntingYard(tokens []token) ([]token, error) {
	var output []token
	var ops []token
	for i := 0; i < len(tokens); i++ {
		tk := tokens[i]
		switch tk.typ {
		case tokenIdentifier:
			output = append(output, tk)
		case tokenNot:
			for len(ops) > 0 && ops[len(ops)-1].typ != tokenLParen && precedence(ops[len(ops)-1]) > precedence(tk) {
				output = append(output, ops[len(ops)-1])
				ops = ops[:len(ops)-1]
			}
			ops = append(ops, tk)
		case tokenAnd, tokenOr:
			for len(ops) > 0 && precedence(ops[len(ops)-1]) >= precedence(tk) {
				if ops[len(ops)-1].typ == tokenLParen {
					break
				}
				output = append(output, ops[len(ops)-1])
				ops = ops[:len(ops)-1]
			}
			ops = append(ops, tk)
		case tokenLParen:
			ops = append(ops, tk)
		case tokenRParen:
			found := false
			for len(ops) > 0 {
				op := ops[len(ops)-1]
				ops = ops[:len(ops)-1]
				if op.typ == tokenLParen {
					found = true
					break
				}
				output = append(output, op)
			}
			if !found {
				return nil, fmt.Errorf("mismatched parentheses in expression")
			}
		default:
			return nil, fmt.Errorf("unsupported token encountered")
		}
	}
	for len(ops) > 0 {
		op := ops[len(ops)-1]
		ops = ops[:len(ops)-1]
		if op.typ == tokenLParen || op.typ == tokenRParen {
			return nil, fmt.Errorf("mismatched parentheses in expression")
		}
		output = append(output, op)
	}
	return output, nil
}

func precedence(t token) int {
	switch t.typ {
	case tokenNot:
		return 3
	case tokenAnd:
		return 2
	case tokenOr:
		return 1
	default:
		return 0
	}
}
